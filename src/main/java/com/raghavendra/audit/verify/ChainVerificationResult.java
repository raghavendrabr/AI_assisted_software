package com.raghavendra.audit.verify;

import java.util.UUID;

/**
 * Outcome of a full chain verification.
 *
 * <p>When {@code intact} is true, the failure fields are null. When false, they identify the
 * FIRST inconsistency found while walking the chain in sequence order.
 *
 * @param intact                   whether the whole chain verified
 * @param verifiedRecords          number of records successfully verified before any failure
 *                                 (equals the total when intact)
 * @param firstInconsistentSequence sequence number of the first inconsistent record (null if intact)
 * @param eventId                  event id at the first inconsistency (null if intact/unknown)
 * @param violationType            the kind of violation (null if intact)
 * @param detail                   human-readable explanation (null if intact)
 */
public record ChainVerificationResult(
        boolean intact,
        long verifiedRecords,
        Long firstInconsistentSequence,
        UUID eventId,
        ChainViolationType violationType,
        String detail
) {
    public static ChainVerificationResult intact(long verifiedRecords) {
        return new ChainVerificationResult(true, verifiedRecords, null, null, null, null);
    }

    public static ChainVerificationResult broken(
            long verifiedRecords, long sequence, UUID eventId,
            ChainViolationType type, String detail) {
        return new ChainVerificationResult(false, verifiedRecords, sequence, eventId, type, detail);
    }
}
