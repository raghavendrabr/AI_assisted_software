package com.raghavendra.audit.verify;

import com.raghavendra.audit.amendment.domain.AuditAmendmentEntity;
import com.raghavendra.audit.amendment.domain.AuditAmendmentRepository;
import com.raghavendra.audit.common.hash.HexFormatUtil;
import com.raghavendra.audit.common.hash.ProtectedAmendmentProjection;
import com.raghavendra.audit.common.hash.ProtectedEventProjection;
import com.raghavendra.audit.common.hash.Sha256Hasher;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.redaction.RedactablePayloadProcessor;
import com.raghavendra.audit.retention.ArchiveManifestHasher;
import com.raghavendra.audit.retention.domain.ArchiveManifestEntity;
import com.raghavendra.audit.retention.domain.ArchiveManifestRepository;
import com.raghavendra.audit.retention.domain.AuditEventArchiveRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Walks the base-event chain (active UNION archived, as ONE ordered chain) and the amendment
 * chain, and confirms consistency — including that redactions are amendment-backed and that
 * every archived range is covered by an intact manifest + ARCHIVE amendment.
 *
 * <p>Base content hashes are recomputed over the redaction-stable "hash payload" (redactable
 * envelopes contribute {salt, commitment}, never the plaintext value). Archived records are read
 * from {@code audit_event_archive} and merged with active records by {@code sequenceNumber}, so
 * archival never produces a false break.
 */
@Service
public class ChainVerificationService {

    private final AuditEventRepository eventRepository;
    private final AuditEventArchiveRepository archiveRepository;
    private final ArchiveManifestRepository manifestRepository;
    private final AuditAmendmentRepository amendmentRepository;
    private final AuditChainHeadRepository chainHeadRepository;
    private final Sha256Hasher hasher;
    private final ArchiveManifestHasher manifestHasher;
    private final RedactablePayloadProcessor payloadProcessor;
    private final ObjectMapper mapper = new ObjectMapper();

    public ChainVerificationService(
            AuditEventRepository eventRepository,
            AuditEventArchiveRepository archiveRepository,
            ArchiveManifestRepository manifestRepository,
            AuditAmendmentRepository amendmentRepository,
            AuditChainHeadRepository chainHeadRepository,
            Sha256Hasher hasher,
            ArchiveManifestHasher manifestHasher,
            RedactablePayloadProcessor payloadProcessor) {
        this.eventRepository = eventRepository;
        this.archiveRepository = archiveRepository;
        this.manifestRepository = manifestRepository;
        this.amendmentRepository = amendmentRepository;
        this.chainHeadRepository = chainHeadRepository;
        this.hasher = hasher;
        this.manifestHasher = manifestHasher;
        this.payloadProcessor = payloadProcessor;
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public ChainVerificationResult verify() {
        // Merge active + archived events into one sequence-ordered stream.
        List<VerifiableEvent> events = new ArrayList<>();
        eventRepository.findAllByOrderBySequenceNumberAsc().forEach(e -> events.add(VerifiableEvent.of(e)));
        archiveRepository.findAllByOrderBySequenceNumberAsc().forEach(e -> events.add(VerifiableEvent.of(e)));
        events.sort(Comparator.comparingLong(VerifiableEvent::sequenceNumber));

        List<AuditAmendmentEntity> amendments = amendmentRepository.findAllByOrderByAmendmentSeqAsc();

        // 1. Amendment chain (collects authorized redactions).
        AmendmentVerification av = verifyAmendmentChain(amendments);
        if (av.violation != null) {
            return av.violation;
        }

        // 2. Archive manifests: each must be intact and bound by an ARCHIVE amendment, and its
        // range/count/endpoints must match the actual archived records.
        ChainVerificationResult manifestCheck = verifyManifests(amendments);
        if (manifestCheck != null) {
            return manifestCheck;
        }

        // 3. Base chain over the merged stream.
        long verified = 0;
        byte[] priorContentHash = null;
        long expectedSequence = 1;

        for (VerifiableEvent e : events) {
            long seq = e.sequenceNumber();

            if (seq != expectedSequence) {
                return ChainVerificationResult.broken(verified, expectedSequence, e.eventId(),
                        ChainViolationType.SEQUENCE_GAP,
                        "expected sequence " + expectedSequence + " but found " + seq);
            }

            byte[] storedContentHash = e.contentHash();
            if (storedContentHash == null || storedContentHash.length != 32) {
                return ChainVerificationResult.broken(verified, seq, e.eventId(),
                        ChainViolationType.MALFORMED_STORED_HASH, "stored content_hash is not 32 bytes");
            }
            byte[] storedPrevHash = e.previousHash();
            if (storedPrevHash != null && storedPrevHash.length != 32) {
                return ChainVerificationResult.broken(verified, seq, e.eventId(),
                        ChainViolationType.MALFORMED_STORED_HASH, "stored previous_hash is not 32 bytes");
            }
            if (seq == 1 && storedPrevHash != null) {
                return ChainVerificationResult.broken(verified, seq, e.eventId(),
                        ChainViolationType.GENESIS_LINK_VIOLATION, "genesis must have null previous_hash");
            }
            if (seq > 1 && storedPrevHash == null) {
                return ChainVerificationResult.broken(verified, seq, e.eventId(),
                        ChainViolationType.GENESIS_LINK_VIOLATION, "non-genesis must have a previous_hash");
            }
            if (seq > 1 && !Arrays.equals(storedPrevHash, priorContentHash)) {
                return ChainVerificationResult.broken(verified, seq, e.eventId(),
                        ChainViolationType.PREVIOUS_HASH_MISMATCH,
                        "previous_hash does not match the prior record's content_hash");
            }

            ChainVerificationResult redactionCheck = checkRedactableFields(e, av.redactions);
            if (redactionCheck != null) {
                return redactionCheck;
            }

            String hashPayload = payloadProcessor.hashPayloadFromStored(e.payload());
            byte[] recomputed = hasher.contentHash(toProjection(e, storedPrevHash, hashPayload));
            if (!Arrays.equals(recomputed, storedContentHash)) {
                return ChainVerificationResult.broken(verified, seq, e.eventId(),
                        ChainViolationType.CONTENT_HASH_MISMATCH,
                        "recomputed content_hash does not match stored (a field or the payload was modified)");
            }

            verified++;
            priorContentHash = storedContentHash;
            expectedSequence++;
        }

        // 4. Chain-head consistency (event tip + amendment tip).
        AuditChainHeadEntity head = chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID).orElse(null);
        if (head == null) {
            return ChainVerificationResult.broken(verified, verified, null,
                    ChainViolationType.CHAIN_HEAD_MISMATCH, "chain head row is missing");
        }
        if (head.getCurrentSequence() != verified || !Arrays.equals(head.getCurrentHash(), priorContentHash)) {
            return ChainVerificationResult.broken(verified, verified, null,
                    ChainViolationType.CHAIN_HEAD_MISMATCH, "chain head does not match the actual event tip");
        }
        if (head.getLastAmendmentSeq() != av.count || !Arrays.equals(head.getAmendmentHeadHash(), av.tipHash)) {
            return ChainVerificationResult.broken(verified, verified, null,
                    ChainViolationType.CHAIN_HEAD_MISMATCH, "chain head does not match the actual amendment tip");
        }

        return ChainVerificationResult.intact(verified);
    }

    // ---- archive manifests --------------------------------------------------------------

    private ChainVerificationResult verifyManifests(List<AuditAmendmentEntity> amendments) {
        List<ArchiveManifestEntity> manifests = manifestRepository.findAllByOrderByFromSequenceAsc();
        // Index ARCHIVE amendments by bound manifestId for cross-checking.
        Set<String> archiveAmendmentManifestKeys = new HashSet<>();
        for (AuditAmendmentEntity a : amendments) {
            if ("ARCHIVE".equals(a.getOperation())) {
                JsonNode d = readTree(a.getDetail());
                if (d != null && d.has("manifestId") && d.has("manifestHash")) {
                    archiveAmendmentManifestKeys.add(d.get("manifestId").asString() + "#" + d.get("manifestHash").asString());
                }
            }
        }

        for (ArchiveManifestEntity m : manifests) {
            // (a) manifest_hash must recompute from the manifest fields.
            byte[] recomputed = manifestHasher.hash(m.getManifestId(), m.getFromSequence(),
                    m.getToSequence(), m.getRecordCount(), m.getFirstHash(), m.getLastHash(),
                    m.getArchivedAt(), m.getAuthorizedBy());
            if (!Arrays.equals(recomputed, m.getManifestHash())) {
                return ChainVerificationResult.broken(m.getFromSequence(), m.getFromSequence(), null,
                        ChainViolationType.ARCHIVE_PROOF_MISMATCH,
                        "archive manifest hash does not match its fields");
            }

            // (b) an intact ARCHIVE amendment must bind this manifest (id + hash).
            String key = m.getManifestId() + "#" + HexFormatUtil.toLowerHex(m.getManifestHash());
            if (!archiveAmendmentManifestKeys.contains(key)) {
                return ChainVerificationResult.broken(m.getFromSequence(), m.getFromSequence(), null,
                        ChainViolationType.ARCHIVE_PROOF_MISMATCH,
                        "no intact ARCHIVE amendment binds manifest " + m.getManifestId());
            }

            // (c) the actual archived records for the range must match count + endpoints.
            List<com.raghavendra.audit.retention.domain.AuditEventArchiveEntity> inRange =
                    archiveRepository.findAllByOrderBySequenceNumberAsc().stream()
                            .filter(a -> a.getSequenceNumber() >= m.getFromSequence()
                                    && a.getSequenceNumber() <= m.getToSequence())
                            .toList();
            if (inRange.size() != m.getRecordCount()) {
                return ChainVerificationResult.broken(m.getFromSequence(), m.getFromSequence(), null,
                        ChainViolationType.ARCHIVE_PROOF_MISMATCH,
                        "archived record count does not match manifest (missing/duplicated archived record)");
            }
            if (!Arrays.equals(inRange.get(0).getContentHash(), m.getFirstHash())
                    || !Arrays.equals(inRange.get(inRange.size() - 1).getContentHash(), m.getLastHash())) {
                return ChainVerificationResult.broken(m.getFromSequence(), m.getFromSequence(), null,
                        ChainViolationType.ARCHIVE_PROOF_MISMATCH,
                        "archived range endpoints do not match manifest first/last hash");
            }
        }
        return null;
    }

    // ---- amendment chain ----------------------------------------------------------------

    private record AmendmentVerification(
            ChainVerificationResult violation, long count, byte[] tipHash, Set<String> redactions) {
    }

    private AmendmentVerification verifyAmendmentChain(List<AuditAmendmentEntity> amendments) {
        long expected = 1;
        byte[] prior = null;
        Set<String> redactions = new HashSet<>();

        for (AuditAmendmentEntity a : amendments) {
            long seq = a.getAmendmentSeq();
            byte[] stored = a.getContentHash();
            byte[] prev = a.getPreviousAmendmentHash();

            if (seq != expected
                    || stored == null || stored.length != 32
                    || (prev != null && prev.length != 32)
                    || (seq == 1 && prev != null)
                    || (seq > 1 && prev == null)
                    || (seq > 1 && !Arrays.equals(prev, prior))) {
                return new AmendmentVerification(
                        ChainVerificationResult.broken(seq - 1, seq, a.getAmendmentId(),
                                ChainViolationType.AMENDMENT_CHAIN_BROKEN,
                                "amendment chain linkage/sequence/hash is invalid at seq " + seq),
                        0, null, redactions);
            }

            byte[] recomputed = hasher.amendmentContentHash(new ProtectedAmendmentProjection(
                    a.getSchemaVersion(), seq, a.getAmendmentId().toString(), a.getOperation(),
                    a.getTargetSequenceNumber(), a.getDetail(), a.getActorId(), a.getRecordedAt(), prev));
            if (!Arrays.equals(recomputed, stored)) {
                return new AmendmentVerification(
                        ChainVerificationResult.broken(seq - 1, seq, a.getAmendmentId(),
                                ChainViolationType.AMENDMENT_CHAIN_BROKEN,
                                "amendment content_hash does not match (an amendment was modified)"),
                        0, null, redactions);
            }

            if ("REDACTION".equals(a.getOperation()) && a.getTargetSequenceNumber() != null) {
                String field = readField(a.getDetail());
                if (field != null) {
                    redactions.add(a.getTargetSequenceNumber() + "#" + field);
                }
            }

            prior = stored;
            expected++;
        }
        return new AmendmentVerification(null, expected - 1, prior, redactions);
    }

    // ---- redactable-field checks --------------------------------------------------------

    private ChainVerificationResult checkRedactableFields(VerifiableEvent e, Set<String> redactions) {
        JsonNode payload = readTree(e.payload());
        if (payload == null || !payload.isObject()) {
            return null;
        }
        for (String field : fieldNames(payload)) {
            JsonNode env = payload.get(field);
            if (env == null || !env.isObject() || !env.has("salt") || !env.has("commitment")) {
                continue;
            }
            JsonNode value = env.get("value");
            if (value == null || value.isNull()) {
                if (!redactions.contains(e.sequenceNumber() + "#" + field)) {
                    return ChainVerificationResult.broken(
                            e.sequenceNumber() - 1, e.sequenceNumber(), e.eventId(),
                            ChainViolationType.REDACTION_UNBACKED,
                            "field '" + field + "' is redacted (null) with no authorized REDACTION amendment");
                }
            } else {
                byte[] salt = decodeHex(env.get("salt").asString());
                String recomputed = payloadProcessor.commitment(e.eventId().toString(), field, salt, value);
                if (!recomputed.equals(env.get("commitment").asString())) {
                    return ChainVerificationResult.broken(
                            e.sequenceNumber() - 1, e.sequenceNumber(), e.eventId(),
                            ChainViolationType.COMMITMENT_MISMATCH,
                            "field '" + field + "' value does not match its commitment (value/salt tampered)");
                }
            }
        }
        return null;
    }

    // ---- helpers ------------------------------------------------------------------------

    private ProtectedEventProjection toProjection(VerifiableEvent e, byte[] previousHash, String hashPayload) {
        return new ProtectedEventProjection(
                e.schemaVersion(), e.sequenceNumber(), e.eventId().toString(),
                e.actorId(), e.actorType(), e.action(), e.resourceType(),
                e.resourceId(), e.outcome(), e.businessReason(),
                e.eventTimestamp(), e.recordedAt(), hashPayload, previousHash);
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
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                    + Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        return out;
    }
}
