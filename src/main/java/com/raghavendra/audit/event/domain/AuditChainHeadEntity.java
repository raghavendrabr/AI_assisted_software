package com.raghavendra.audit.event.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.OffsetDateTime;

/**
 * JPA mapping for the singleton {@code audit_chain_head} row (schema from V1, ADR 0002).
 *
 * <p>The append service locks this row with {@code SELECT ... FOR UPDATE} inside the append
 * transaction to serialize writes and keep one deterministic chain. There is exactly one row,
 * with {@code id = 1}.
 */
@Entity
@Table(name = "audit_chain_head")
public class AuditChainHeadEntity {

    /** Fixed singleton id (always 1). */
    public static final short SINGLETON_ID = 1;

    @Id
    @Column(name = "id", nullable = false)
    private Short id;

    @Column(name = "current_sequence", nullable = false)
    private long currentSequence;

    @Column(name = "current_hash")
    private byte[] currentHash;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @Column(name = "last_amendment_seq", nullable = false)
    private long lastAmendmentSeq;

    @Column(name = "amendment_head_hash")
    private byte[] amendmentHeadHash;

    protected AuditChainHeadEntity() {
        // for JPA
    }

    public Short getId() {
        return id;
    }

    public long getCurrentSequence() {
        return currentSequence;
    }

    public byte[] getCurrentHash() {
        return currentHash == null ? null : currentHash.clone();
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }

    /**
     * Advance the head to a newly appended event. Called only inside the append transaction
     * while this row is locked FOR UPDATE.
     */
    public void advanceTo(long newSequence, byte[] newHash, OffsetDateTime updatedAt) {
        this.currentSequence = newSequence;
        this.currentHash = newHash.clone();
        this.updatedAt = updatedAt;
    }

    public long getLastAmendmentSeq() {
        return lastAmendmentSeq;
    }

    public byte[] getAmendmentHeadHash() {
        return amendmentHeadHash == null ? null : amendmentHeadHash.clone();
    }

    /**
     * Advance the amendment-chain tip. Called only inside the redaction/amendment transaction
     * while this row is locked FOR UPDATE.
     */
    public void advanceAmendment(long newSeq, byte[] newHash, OffsetDateTime updatedAt) {
        this.lastAmendmentSeq = newSeq;
        this.amendmentHeadHash = newHash.clone();
        this.updatedAt = updatedAt;
    }

    /**
     * Reset the head to the empty-chain state (both chains empty). Intended for test fixtures
     * that clear the chain; production appends only ever advance the head forward.
     */
    public void resetToEmpty(OffsetDateTime updatedAt) {
        this.currentSequence = 0L;
        this.currentHash = null;
        this.lastAmendmentSeq = 0L;
        this.amendmentHeadHash = null;
        this.updatedAt = updatedAt;
    }
}
