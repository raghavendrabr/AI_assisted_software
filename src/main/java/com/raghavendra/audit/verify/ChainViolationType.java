package com.raghavendra.audit.verify;

/**
 * The kinds of inconsistency the chain verifier can detect. Each maps to a specific class of
 * tampering or corruption discovered while walking the chain in sequence order.
 */
public enum ChainViolationType {

    /** A stored field (or its recomputed content hash) no longer matches — a modified field. */
    CONTENT_HASH_MISMATCH,

    /** The stored content hash is not exactly 32 bytes — a malformed/corrupt stored hash. */
    MALFORMED_STORED_HASH,

    /** A record's previous_hash does not equal the actual prior record's content hash. */
    PREVIOUS_HASH_MISMATCH,

    /** The genesis record (sequence 1) has a non-null previous_hash, or a later record is null. */
    GENESIS_LINK_VIOLATION,

    /** A gap in sequence numbers — a missing/deleted record. */
    SEQUENCE_GAP,

    /** The audit_chain_head row does not match the actual chain tip (sequence or hash). */
    CHAIN_HEAD_MISMATCH,

    /** An amendment record's recomputed content hash / linkage is broken. */
    AMENDMENT_CHAIN_BROKEN,

    /** A redactable field's plaintext is null but no authorized REDACTION amendment backs it. */
    REDACTION_UNBACKED,

    /** A present redactable value does not match its stored commitment (value/salt tampered). */
    COMMITMENT_MISMATCH,

    /** An archive manifest's count/range/hash does not match its archived records or ARCHIVE amendment. */
    ARCHIVE_PROOF_MISMATCH
}
