package com.raghavendra.audit.verify;

import com.raghavendra.audit.common.hash.ProtectedEventProjection;
import com.raghavendra.audit.common.hash.Sha256Hasher;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;

/**
 * Walks the full audit chain in sequence order and reports whether it is intact, or the first
 * inconsistency and its type. This is the read-side counterpart to the append service: it
 * recomputes each record's content hash from its stored fields using the exact same canonical
 * scheme (ADR 0003), so any post-hoc modification is detectable.
 *
 * <p>Detected violations (first one wins, in walk order):
 * <ul>
 *   <li>{@code MALFORMED_STORED_HASH} — a stored content hash that is not 32 bytes;</li>
 *   <li>{@code CONTENT_HASH_MISMATCH} — a modified field OR modified payload (recomputed hash
 *       differs from the stored hash);</li>
 *   <li>{@code GENESIS_LINK_VIOLATION} — genesis has a previous_hash, or a later record lacks one;</li>
 *   <li>{@code PREVIOUS_HASH_MISMATCH} — a record's previous_hash ≠ the prior record's content hash;</li>
 *   <li>{@code SEQUENCE_GAP} — a missing/deleted sequence number;</li>
 *   <li>{@code CHAIN_HEAD_MISMATCH} — the head row disagrees with the actual chain tip.</li>
 * </ul>
 */
@Service
public class ChainVerificationService {

    private final AuditEventRepository eventRepository;
    private final AuditChainHeadRepository chainHeadRepository;
    private final Sha256Hasher hasher;

    public ChainVerificationService(
            AuditEventRepository eventRepository,
            AuditChainHeadRepository chainHeadRepository,
            Sha256Hasher hasher) {
        this.eventRepository = eventRepository;
        this.chainHeadRepository = chainHeadRepository;
        this.hasher = hasher;
    }

    /**
     * Verification runs in a REPEATABLE_READ read-only transaction so the event scan and the
     * chain-head read observe ONE consistent snapshot. Without this, a concurrent append
     * committing between the two reads could make the head look ahead of the scanned events
     * and produce a false {@code CHAIN_HEAD_MISMATCH}. REPEATABLE_READ (PostgreSQL snapshot
     * isolation) pins the snapshot at the first statement, so verification always sees a
     * coherent point-in-time chain.
     */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public ChainVerificationResult verify() {
        List<AuditEventEntity> events = eventRepository.findAllByOrderBySequenceNumberAsc();

        long verified = 0;
        byte[] priorContentHash = null; // content hash of the previously verified record
        long expectedSequence = 1;

        for (AuditEventEntity e : events) {
            long seq = e.getSequenceNumber();

            // 1. Sequence gap / duplicate detection: sequences must be exactly 1,2,3,...
            if (seq != expectedSequence) {
                return ChainVerificationResult.broken(verified, expectedSequence, e.getEventId(),
                        ChainViolationType.SEQUENCE_GAP,
                        "expected sequence " + expectedSequence + " but found " + seq);
            }

            // 2. Malformed stored hash: content hash must be exactly 32 bytes.
            byte[] storedContentHash = e.getContentHash();
            if (storedContentHash == null || storedContentHash.length != 32) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.MALFORMED_STORED_HASH,
                        "stored content_hash is not 32 bytes");
            }
            byte[] storedPrevHash = e.getPreviousHash();
            if (storedPrevHash != null && storedPrevHash.length != 32) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.MALFORMED_STORED_HASH,
                        "stored previous_hash is present but not 32 bytes");
            }

            // 3. Genesis linkage: seq 1 => previous_hash null; seq > 1 => previous_hash present.
            if (seq == 1 && storedPrevHash != null) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.GENESIS_LINK_VIOLATION,
                        "genesis record must have null previous_hash");
            }
            if (seq > 1 && storedPrevHash == null) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.GENESIS_LINK_VIOLATION,
                        "non-genesis record must have a previous_hash");
            }

            // 4. Previous-hash linkage: previous_hash must equal the prior record's content hash.
            if (seq > 1 && !Arrays.equals(storedPrevHash, priorContentHash)) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.PREVIOUS_HASH_MISMATCH,
                        "previous_hash does not match the prior record's content_hash");
            }

            // 5. Content-hash recomputation: detects a modified field OR modified payload.
            byte[] recomputed = hasher.contentHash(toProjection(e, storedPrevHash));
            if (!Arrays.equals(recomputed, storedContentHash)) {
                return ChainVerificationResult.broken(verified, seq, e.getEventId(),
                        ChainViolationType.CONTENT_HASH_MISMATCH,
                        "recomputed content_hash does not match the stored content_hash "
                                + "(a field or the payload was modified)");
            }

            verified++;
            priorContentHash = storedContentHash;
            expectedSequence++;
        }

        // 6. Chain-head consistency: the head must reflect the actual tip.
        AuditChainHeadEntity head = chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .orElse(null);
        ChainVerificationResult headCheck = verifyHead(head, verified, priorContentHash);
        if (headCheck != null) {
            return headCheck;
        }

        return ChainVerificationResult.intact(verified);
    }

    private ChainVerificationResult verifyHead(AuditChainHeadEntity head, long verified, byte[] tipHash) {
        if (head == null) {
            return ChainVerificationResult.broken(verified, verified, null,
                    ChainViolationType.CHAIN_HEAD_MISMATCH, "chain head row is missing");
        }
        if (head.getCurrentSequence() != verified) {
            return ChainVerificationResult.broken(verified, verified, null,
                    ChainViolationType.CHAIN_HEAD_MISMATCH,
                    "chain head sequence " + head.getCurrentSequence()
                            + " does not match the actual tip " + verified);
        }
        byte[] headHash = head.getCurrentHash();
        // Empty chain: tip hash null; non-empty: head hash must equal the last content hash.
        if (!Arrays.equals(headHash, tipHash)) {
            return ChainVerificationResult.broken(verified, verified, null,
                    ChainViolationType.CHAIN_HEAD_MISMATCH,
                    "chain head current_hash does not match the actual tip content_hash");
        }
        return null;
    }

    private ProtectedEventProjection toProjection(AuditEventEntity e, byte[] previousHash) {
        return new ProtectedEventProjection(
                e.getSchemaVersion(),
                e.getSequenceNumber(),
                e.getEventId().toString(),
                e.getActorId(),
                e.getActorType(),
                e.getAction(),
                e.getResourceType(),
                e.getResourceId(),
                e.getOutcome(),
                e.getBusinessReason(),
                e.getEventTimestamp(),
                e.getRecordedAt(),
                e.getPayload(),
                previousHash
        );
    }
}
