package com.raghavendra.audit.amendment.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * JPA mapping for an immutable {@code audit_amendment} record (schema from V2). Written once;
 * never updated.
 */
@Entity
@Table(name = "audit_amendment")
public class AuditAmendmentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "amendment_id", nullable = false, updatable = false)
    private UUID amendmentId;

    @Column(name = "amendment_seq", nullable = false, updatable = false)
    private Long amendmentSeq;

    @Column(name = "operation", nullable = false, updatable = false)
    private String operation;

    @Column(name = "target_sequence_number", updatable = false)
    private Long targetSequenceNumber;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "detail", nullable = false, updatable = false, columnDefinition = "jsonb")
    private String detail;

    @Column(name = "actor_id", nullable = false, updatable = false)
    private String actorId;

    @Column(name = "recorded_at", nullable = false, updatable = false)
    private OffsetDateTime recordedAt;

    @Column(name = "schema_version", nullable = false, updatable = false)
    private int schemaVersion;

    @Column(name = "previous_amendment_hash", updatable = false)
    private byte[] previousAmendmentHash;

    @Column(name = "content_hash", nullable = false, updatable = false)
    private byte[] contentHash;

    protected AuditAmendmentEntity() {
    }

    public AuditAmendmentEntity(UUID amendmentId, Long amendmentSeq, String operation,
                                Long targetSequenceNumber, String detail, String actorId,
                                OffsetDateTime recordedAt, int schemaVersion,
                                byte[] previousAmendmentHash, byte[] contentHash) {
        this.amendmentId = amendmentId;
        this.amendmentSeq = amendmentSeq;
        this.operation = operation;
        this.targetSequenceNumber = targetSequenceNumber;
        this.detail = detail;
        this.actorId = actorId;
        this.recordedAt = recordedAt;
        this.schemaVersion = schemaVersion;
        this.previousAmendmentHash = previousAmendmentHash == null ? null : previousAmendmentHash.clone();
        this.contentHash = contentHash.clone();
    }

    public Long getId() {
        return id;
    }

    public UUID getAmendmentId() {
        return amendmentId;
    }

    public Long getAmendmentSeq() {
        return amendmentSeq;
    }

    public String getOperation() {
        return operation;
    }

    public Long getTargetSequenceNumber() {
        return targetSequenceNumber;
    }

    public String getDetail() {
        return detail;
    }

    public String getActorId() {
        return actorId;
    }

    public OffsetDateTime getRecordedAt() {
        return recordedAt;
    }

    public int getSchemaVersion() {
        return schemaVersion;
    }

    public byte[] getPreviousAmendmentHash() {
        return previousAmendmentHash == null ? null : previousAmendmentHash.clone();
    }

    public byte[] getContentHash() {
        return contentHash.clone();
    }
}
