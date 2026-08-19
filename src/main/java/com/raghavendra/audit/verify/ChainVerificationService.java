package com.raghavendra.audit.verify;

import com.raghavendra.audit.amendment.domain.AuditAmendmentEntity;
import com.raghavendra.audit.amendment.domain.AuditAmendmentRepository;
import com.raghavendra.audit.common.hash.ProtectedAmendmentProjection;
import com.raghavendra.audit.common.hash.ProtectedEventProjection;
import com.raghavendra.audit.common.hash.Sha256Hasher;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.redaction.RedactablePayloadProcessor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Walks BOTH chains — the base-event chain and the amendment chain — and confirms consistency,
 * including that every redaction of a plaintext value is backed by an authorized amendment.
 *
 * <p>Base content hashes are recomputed over the redaction-stable "hash payload" (redactable
 * envelopes contribute {salt, commitment}, never the plaintext value), so a legitimately
 * redacted event still verifies. Additional checks (in walk order per record):
 * {@code COMMITMENT_MISMATCH} for a present value whose commitment doesn't match, and
 * {@code REDACTION_UNBACKED} for a null value with no backing REDACTION amendment.
 */
@Service
public class ChainVerificationService {

    private final AuditEventRepository eventRepository;
    private final AuditAmendmentRepository amendmentRepository;
    private final AuditChainHeadRepository chainHeadRepository;
    private final Sha256Hasher hasher;
    private final RedactablePayloadProcessor payloadProcessor;
    private final ObjectMapper mapper = new ObjectMapper();

    public ChainVerificationService(
            AuditEventRepository eventRepository,
            AuditAmendmentRepository amendmentRepository,
            AuditChainHeadRepository chainHeadRepository,
            Sha256Hasher hasher,
            RedactablePayloadProcessor payloadProcessor) {
        this.eventRepository = eventRepository;
        this.amendmentRepository = amendmentRepository;
        this.chainHeadRepository = chainHeadRepository;
        this.hasher = hasher;
        this.payloadProcessor = payloadProcessor;
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public ChainVerificationResult verify() {
        List<AuditEventEntity> events = eventRepository.findAllByOrderBySequenceNumberAsc();
        List<AuditAmendmentEntity> amendments = amendmentRepository.findAllByOrderByAmendmentSeqAsc();

        // 1. Verify the amendment chain first and collect authorized (sequence, field) redactions.
        AmendmentVerification av = verifyAmendmentChain(amendments);
        if (av.violation != null) {
            return av.violation;
        }

        long verified = 0;
        byte[] priorContentHash = null;
        long expectedSequence = 1;

        for (AuditEventEntity e : events) {
            long seq = e.getSequenceNumber();

            if (seq != expectedSequence) {
                return ChainVerificationResult.broken(verified, expectedSequence, e.getEventId(),
                        ChainViolationType.SEQUENCE_GAP,
                        "expected sequence " + expectedSequence + " but found " + seq);
            }

            byte[] storedContentHash = e.getContentHash();
            if (storedContentHash == null || storedContentHash.length != 32) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.MALFORMED_STORED_HASH, "stored content_hash is not 32 bytes");
            }
            byte[] storedPrevHash = e.getPreviousHash();
            if (storedPrevHash != null && storedPrevHash.length != 32) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.MALFORMED_STORED_HASH, "stored previous_hash is not 32 bytes");
            }
            if (seq == 1 && storedPrevHash != null) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.GENESIS_LINK_VIOLATION, "genesis must have null previous_hash");
            }
            if (seq > 1 && storedPrevHash == null) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.GENESIS_LINK_VIOLATION, "non-genesis must have a previous_hash");
            }
            if (seq > 1 && !Arrays.equals(storedPrevHash, priorContentHash)) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.PREVIOUS_HASH_MISMATCH,
                        "previous_hash does not match the prior record's content_hash");
            }

            // Redactable-field checks: present value must match its commitment; null value must
            // be backed by an authorized REDACTION amendment for this (sequence, field).
            ChainVerificationResult redactionCheck = checkRedactableFields(e, av.redactions);
            if (redactionCheck != null) {
                return redactionCheck;
            }

            // Content-hash recomputation over the redaction-stable hash payload.
            String hashPayload = payloadProcessor.hashPayloadFromStored(e.getPayload());
            byte[] recomputed = hasher.contentHash(toProjection(e, storedPrevHash, hashPayload));
            if (!Arrays.equals(recomputed, storedContentHash)) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.CONTENT_HASH_MISMATCH,
                        "recomputed content_hash does not match stored (a field or the payload was modified)");
            }

            verified++;
            priorContentHash = storedContentHash;
            expectedSequence++;
        }

        // Chain-head consistency: both tips.
        AuditChainHeadEntity head = chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID).orElse(null);
        if (head == null) {
            return ChainVerificationResult.broken(verified, verified, null,
                    ChainViolationType.CHAIN_HEAD_MISMATCH, "chain head row is missing");
        }
        if (head.getCurrentSequence() != verified || !Arrays.equals(head.getCurrentHash(), priorContentHash)) {
            return ChainVerificationResult.broken(verified, verified, null,
                    ChainViolationType.CHAIN_HEAD_MISMATCH,
                    "chain head does not match the actual event tip");
        }
        if (head.getLastAmendmentSeq() != av.count || !Arrays.equals(head.getAmendmentHeadHash(), av.tipHash)) {
            return ChainVerificationResult.broken(verified, verified, null,
                    ChainViolationType.CHAIN_HEAD_MISMATCH,
                    "chain head does not match the actual amendment tip");
        }

        return ChainVerificationResult.intact(verified);
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

    private ChainVerificationResult checkRedactableFields(AuditEventEntity e, Set<String> redactions) {
        JsonNode payload = readTree(e.getPayload());
        if (payload == null || !payload.isObject()) {
            return null;
        }
        for (String field : fieldNames(payload)) {
            JsonNode env = payload.get(field);
            if (env == null || !env.isObject() || !env.has("salt") || !env.has("commitment")) {
                continue; // not a redactable envelope
            }
            JsonNode value = env.get("value");
            if (value == null || value.isNull()) {
                // Null plaintext requires a backing REDACTION amendment.
                if (!redactions.contains(e.getSequenceNumber() + "#" + field)) {
                    return ChainVerificationResult.broken(
                            e.getSequenceNumber() - 1, e.getSequenceNumber(), e.getEventId(),
                            ChainViolationType.REDACTION_UNBACKED,
                            "field '" + field + "' is redacted (null) with no authorized REDACTION amendment");
                }
            } else {
                // Present value must match its commitment (bound to eventId + field path).
                byte[] salt = decodeHex(env.get("salt").asString());
                String recomputed = payloadProcessor.commitment(
                        e.getEventId().toString(), field, salt, value);
                if (!recomputed.equals(env.get("commitment").asString())) {
                    return ChainVerificationResult.broken(
                            e.getSequenceNumber() - 1, e.getSequenceNumber(), e.getEventId(),
                            ChainViolationType.COMMITMENT_MISMATCH,
                            "field '" + field + "' value does not match its commitment (value/salt tampered)");
                }
            }
        }
        return null;
    }

    // ---- helpers ------------------------------------------------------------------------

    private ProtectedEventProjection toProjection(AuditEventEntity e, byte[] previousHash, String hashPayload) {
        return new ProtectedEventProjection(
                e.getSchemaVersion(), e.getSequenceNumber(), e.getEventId().toString(),
                e.getActorId(), e.getActorType(), e.getAction(), e.getResourceType(),
                e.getResourceId(), e.getOutcome(), e.getBusinessReason(),
                e.getEventTimestamp(), e.getRecordedAt(), hashPayload, previousHash);
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
