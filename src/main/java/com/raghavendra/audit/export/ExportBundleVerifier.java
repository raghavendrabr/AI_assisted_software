package com.raghavendra.audit.export;

import com.raghavendra.audit.common.hash.CanonicalJsonSerializer;
import com.raghavendra.audit.common.hash.HexFormatUtil;
import com.raghavendra.audit.common.hash.ProtectedAmendmentProjection;
import com.raghavendra.audit.common.hash.ProtectedEventProjection;
import com.raghavendra.audit.common.hash.Sha256Hasher;
import com.raghavendra.audit.redaction.RedactablePayloadProcessor;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Standalone verifier for an {@link ExportBundle}. Depends only on the hashing library (no Spring,
 * no database), so a recipient can run it offline.
 *
 * <p>Checks, in order:
 * <ol>
 *   <li><b>Signature</b> — Ed25519 over {@code SHA-256(canonical(manifest))}.</li>
 *   <li><b>Events</b> — recompute each content hash (redaction-stable); match the stated hash and
 *       {@code manifest.eventHashes} in order; reject duplicate event ids/sequences; reject counts
 *       that disagree (removal/insertion).</li>
 *   <li><b>Filter membership</b> — every exported event actually matches the signed
 *       {@code filterType}/{@code filterValue}.</li>
 *   <li><b>Amendments</b> — recompute each amendment content hash; match stated hash and
 *       {@code manifest.amendmentHashes} in order; verify amendment sequence continuity and
 *       previous-hash linkage; reject modified/reordered/removed/inserted/duplicated amendments.</li>
 *   <li><b>Redaction consistency</b> — every null redactable field is backed by a valid REDACTION
 *       amendment in the bundle; every present redactable value matches its commitment.</li>
 * </ol>
 */
public final class ExportBundleVerifier {

    private final CanonicalJsonSerializer serializer = new CanonicalJsonSerializer();
    private final Sha256Hasher hasher = new Sha256Hasher(serializer);
    private final RedactablePayloadProcessor payloadProcessor = new RedactablePayloadProcessor();
    private final ObjectMapper mapper = new ObjectMapper();

    public record Result(boolean valid, String detail) {
        static Result ok() { return new Result(true, "bundle is valid"); }
        static Result fail(String d) { return new Result(false, d); }
    }

    public Result verify(ExportBundle bundle) {
        return verify(bundle, bundle.publicKeyBase64());
    }

    public Result verify(ExportBundle bundle, String trustedPublicKeyBase64) {
        try {
            ExportBundle.Manifest m = bundle.manifest();

            // 1. Signature over the recomputed manifest digest.
            byte[] digest = ExportManifestCanonicalizer.digest(m);
            if (!verifySignature(digest, bundle.signatureBase64(), trustedPublicKeyBase64)) {
                return Result.fail("Ed25519 signature does not verify against the manifest");
            }

            List<ExportBundle.ExportedEvent> events = bundle.events();
            List<String> eventHashes = m.eventHashes();

            // 2a. Count consistency.
            if (events.size() != m.recordCount() || eventHashes.size() != events.size()) {
                return Result.fail("record count / event-hash list length mismatch (removal or insertion)");
            }

            // 2b. Per-event: recompute, order, uniqueness, filter membership.
            Set<String> seenEventIds = new HashSet<>();
            Set<Long> seenSequences = new HashSet<>();
            for (int i = 0; i < events.size(); i++) {
                ExportBundle.ExportedEvent e = events.get(i);

                if (!seenEventIds.add(e.eventId())) {
                    return Result.fail("duplicate event id in bundle: " + e.eventId());
                }
                if (!seenSequences.add(e.sequenceNumber())) {
                    return Result.fail("duplicate sequence number in bundle: " + e.sequenceNumber());
                }

                // 3. Filter membership.
                if (!matchesFilter(e, m.filterType(), m.filterValue())) {
                    return Result.fail("event at sequence " + e.sequenceNumber()
                            + " does not match the signed filter " + m.filterType() + "=" + m.filterValue());
                }

                String recomputed = recomputeEventHash(e);
                if (!recomputed.equals(e.contentHash())) {
                    return Result.fail("event at sequence " + e.sequenceNumber()
                            + " was modified (recomputed content hash differs)");
                }
                if (!recomputed.equals(eventHashes.get(i))) {
                    return Result.fail("event order/content does not match manifest at index " + i);
                }

                // 5b. Present redactable values must match their commitments.
                Result commitmentCheck = checkCommitments(e);
                if (!commitmentCheck.valid()) {
                    return commitmentCheck;
                }
            }

            // 4. Amendments: recompute, order, sequence continuity, previous-hash linkage.
            List<ExportBundle.ExportedAmendment> amendments = bundle.amendments();
            List<String> amendmentHashes = m.amendmentHashes();
            if (amendments.size() != amendmentHashes.size()) {
                return Result.fail("amendment count / amendment-hash list length mismatch");
            }
            Set<Long> seenAmendmentSeqs = new HashSet<>();
            Set<String> seenAmendmentIds = new HashSet<>();
            Set<String> validRedactions = new HashSet<>(); // "seq#field" backed by a valid REDACTION
            byte[] priorAmendmentHash = null;
            Long priorAmendmentSeq = null;
            for (int i = 0; i < amendments.size(); i++) {
                ExportBundle.ExportedAmendment a = amendments.get(i);

                if (!seenAmendmentSeqs.add(a.amendmentSeq())) {
                    return Result.fail("duplicate amendment sequence in bundle: " + a.amendmentSeq());
                }
                if (!seenAmendmentIds.add(a.amendmentId())) {
                    return Result.fail("duplicate amendment id in bundle: " + a.amendmentId());
                }
                // Order: amendmentSeq must be strictly increasing across the exported list.
                if (priorAmendmentSeq != null && a.amendmentSeq() <= priorAmendmentSeq) {
                    return Result.fail("amendments are not in ascending sequence order (reordered/duplicated)");
                }

                String recomputed = recomputeAmendmentHash(a);
                if (!recomputed.equals(a.contentHash())) {
                    return Result.fail("amendment at seq " + a.amendmentSeq() + " was modified");
                }
                if (!recomputed.equals(amendmentHashes.get(i))) {
                    return Result.fail("amendment order/content does not match manifest at index " + i);
                }

                // previous-hash linkage: each amendment's previousAmendmentHash must equal the
                // prior EXPORTED amendment's content hash when they are consecutive in the global
                // amendment chain (amendmentSeq differs by 1). If there is a gap (amendments not
                // touching exported events were omitted), we cannot assert linkage across the gap.
                if (priorAmendmentSeq != null && a.amendmentSeq() == priorAmendmentSeq + 1) {
                    String prevHex = a.previousAmendmentHash();
                    String expected = HexFormatUtil.toLowerHex(priorAmendmentHash);
                    if (prevHex == null || !prevHex.equals(expected)) {
                        return Result.fail("amendment previous-hash linkage broken at seq " + a.amendmentSeq());
                    }
                }

                if ("REDACTION".equals(a.operation()) && a.targetSequenceNumber() != null) {
                    String field = readField(a.detail());
                    if (field != null) {
                        validRedactions.add(a.targetSequenceNumber() + "#" + field);
                    }
                }
                priorAmendmentHash = decodeHex(a.contentHash());
                priorAmendmentSeq = a.amendmentSeq();
            }

            // 5a. Every null redactable field must be backed by a valid REDACTION amendment.
            for (ExportBundle.ExportedEvent e : events) {
                Result r = checkRedactionsBacked(e, validRedactions);
                if (!r.valid()) {
                    return r;
                }
            }

            return Result.ok();
        } catch (Exception ex) {
            return Result.fail("verification error: " + ex.getMessage());
        }
    }

    // ---- helpers ------------------------------------------------------------------------

    private boolean matchesFilter(ExportBundle.ExportedEvent e, String type, String value) {
        if ("resourceId".equals(type)) {
            return value.equals(e.resourceId());
        }
        if ("actorId".equals(type)) {
            return value.equals(e.actorId());
        }
        return false; // unknown filter type → not a supported bundle
    }

    private Result checkCommitments(ExportBundle.ExportedEvent e) {
        JsonNode payload = readTree(e.payload());
        if (payload == null || !payload.isObject()) {
            return Result.ok();
        }
        for (String field : fieldNames(payload)) {
            JsonNode env = payload.get(field);
            if (env == null || !env.isObject() || !env.has("salt") || !env.has("commitment")) {
                continue;
            }
            JsonNode value = env.get("value");
            if (value != null && !value.isNull()) {
                byte[] salt = decodeHex(env.get("salt").asString());
                String recomputed = payloadProcessor.commitment(e.eventId(), field, salt, value);
                if (!recomputed.equals(env.get("commitment").asString())) {
                    return Result.fail("event " + e.sequenceNumber() + " field '" + field
                            + "' value does not match its commitment");
                }
            }
        }
        return Result.ok();
    }

    private Result checkRedactionsBacked(ExportBundle.ExportedEvent e, Set<String> validRedactions) {
        JsonNode payload = readTree(e.payload());
        if (payload == null || !payload.isObject()) {
            return Result.ok();
        }
        for (String field : fieldNames(payload)) {
            JsonNode env = payload.get(field);
            if (env == null || !env.isObject() || !env.has("salt") || !env.has("commitment")) {
                continue;
            }
            JsonNode value = env.get("value");
            if (value == null || value.isNull()) {
                if (!validRedactions.contains(e.sequenceNumber() + "#" + field)) {
                    return Result.fail("event " + e.sequenceNumber() + " field '" + field
                            + "' is redacted (null) with no backing REDACTION amendment in the bundle");
                }
            }
        }
        return Result.ok();
    }

    private boolean verifySignature(byte[] digest, String signatureB64, String publicKeyB64)
            throws Exception {
        if (publicKeyB64 == null || signatureB64 == null) {
            return false;
        }
        byte[] der = Base64.getDecoder().decode(publicKeyB64);
        PublicKey pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        Signature sig = Signature.getInstance("Ed25519");
        sig.initVerify(pub);
        sig.update(digest);
        return sig.verify(Base64.getDecoder().decode(signatureB64));
    }

    private String recomputeEventHash(ExportBundle.ExportedEvent e) {
        String hashPayload = payloadProcessor.hashPayloadFromStored(e.payload());
        ProtectedEventProjection projection = new ProtectedEventProjection(
                e.schemaVersion(), e.sequenceNumber(), e.eventId(), e.actorId(), e.actorType(),
                e.action(), e.resourceType(), e.resourceId(), e.outcome(), e.businessReason(),
                OffsetDateTime.parse(e.eventTimestamp()), OffsetDateTime.parse(e.recordedAt()),
                hashPayload, e.previousHash() == null ? null : decodeHex(e.previousHash()));
        return HexFormatUtil.toLowerHex(hasher.contentHash(projection));
    }

    private String recomputeAmendmentHash(ExportBundle.ExportedAmendment a) {
        ProtectedAmendmentProjection projection = new ProtectedAmendmentProjection(
                a.schemaVersion(), a.amendmentSeq(), a.amendmentId(), a.operation(),
                a.targetSequenceNumber(), a.detail(), a.actorId(),
                OffsetDateTime.parse(a.recordedAt()),
                a.previousAmendmentHash() == null ? null : decodeHex(a.previousAmendmentHash()));
        return HexFormatUtil.toLowerHex(hasher.amendmentContentHash(projection));
    }

    private JsonNode readTree(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        return mapper.readTree(json);
    }

    private List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.propertyNames().forEach(names::add);
        return names;
    }

    private String readField(String detailJson) {
        JsonNode d = readTree(detailJson);
        return (d != null && d.has("field")) ? d.get("field").asString() : null;
    }

    private byte[] decodeHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                    + Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        return out;
    }
}
