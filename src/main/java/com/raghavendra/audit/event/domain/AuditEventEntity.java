package com.raghavendra.audit.event.domain;

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
 * JPA mapping for the append-only {@code audit_event} table (schema from V1, ADR 0002).
 *
 * <p>This entity is written exactly once (append-only): there is no setter-based update path
 * exposed by the service, and the API never offers update/delete. All integrity-relevant
 * values (hashes, timestamps) are computed by the append service and set at construction.
 */
@Entity
@Table(name = "audit_event")
public class AuditEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", nullable = false, updatable = false)
    private UUID eventId;

    @Column(name = "sequence_number", nullable = false, updatable = false)
    private Long sequenceNumber;

    @Column(name = "actor_id", nullable = false, updatable = false)
    private String actorId;

    @Column(name = "actor_type", nullable = false, updatable = false)
    private String actorType;

    @Column(name = "action", nullable = false, updatable = false)
    private String action;

    @Column(name = "resource_type", nullable = false, updatable = false)
    private String resourceType;

    @Column(name = "resource_id", nullable = false, updatable = false)
    private String resourceId;

    @Column(name = "outcome", nullable = false, updatable = false)
    private String outcome;

    @Column(name = "business_reason", updatable = false)
    private String businessReason;

    @Column(name = "event_timestamp", nullable = false, updatable = false)
    private OffsetDateTime eventTimestamp;

    @Column(name = "recorded_at", nullable = false, updatable = false)
    private OffsetDateTime recordedAt;

    @Column(name = "schema_version", nullable = false, updatable = false)
    private int schemaVersion;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "payload", nullable = false, updatable = false, columnDefinition = "jsonb")
    private String payload;

    @Column(name = "previous_hash", updatable = false)
    private byte[] previousHash;

    @Column(name = "content_hash", nullable = false, updatable = false)
    private byte[] contentHash;

    protected AuditEventEntity() {
        // for JPA
    }

    public AuditEventEntity(
            UUID eventId, Long sequenceNumber, String actorId, String actorType, String action,
            String resourceType, String resourceId, String outcome, String businessReason,
            OffsetDateTime eventTimestamp, OffsetDateTime recordedAt, int schemaVersion,
            String payload, byte[] previousHash, byte[] contentHash) {
        this.eventId = eventId;
        this.sequenceNumber = sequenceNumber;
        this.actorId = actorId;
        this.actorType = actorType;
        this.action = action;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.outcome = outcome;
        this.businessReason = businessReason;
        this.eventTimestamp = eventTimestamp;
        this.recordedAt = recordedAt;
        this.schemaVersion = schemaVersion;
        this.payload = payload;
        this.previousHash = previousHash == null ? null : previousHash.clone();
        this.contentHash = contentHash.clone();
    }

    public Long getId() {
        return id;
    }

    public UUID getEventId() {
        return eventId;
    }

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public String getActorId() {
        return actorId;
    }

    public String getActorType() {
        return actorType;
    }

    public String getAction() {
        return action;
    }

    public String getResourceType() {
        return resourceType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getOutcome() {
        return outcome;
    }

    public String getBusinessReason() {
        return businessReason;
    }

    public OffsetDateTime getEventTimestamp() {
        return eventTimestamp;
    }

    public OffsetDateTime getRecordedAt() {
        return recordedAt;
    }

    public int getSchemaVersion() {
        return schemaVersion;
    }

    public String getPayload() {
        return payload;
    }

    public byte[] getPreviousHash() {
        return previousHash == null ? null : previousHash.clone();
    }

    public byte[] getContentHash() {
        return contentHash.clone();
    }
}
