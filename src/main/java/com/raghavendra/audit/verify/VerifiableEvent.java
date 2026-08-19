package com.raghavendra.audit.verify;

import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.retention.domain.AuditEventArchiveEntity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * A uniform, source-agnostic view of a base event for verification, so the verifier can walk
 * active and archived records as ONE ordered chain. {@code archived} records where the row lives.
 */
record VerifiableEvent(
        long sequenceNumber,
        UUID eventId,
        int schemaVersion,
        String actorId,
        String actorType,
        String action,
        String resourceType,
        String resourceId,
        String outcome,
        String businessReason,
        OffsetDateTime eventTimestamp,
        OffsetDateTime recordedAt,
        String payload,
        byte[] previousHash,
        byte[] contentHash,
        boolean archived
) {
    static VerifiableEvent of(AuditEventEntity e) {
        return new VerifiableEvent(e.getSequenceNumber(), e.getEventId(), e.getSchemaVersion(),
                e.getActorId(), e.getActorType(), e.getAction(), e.getResourceType(),
                e.getResourceId(), e.getOutcome(), e.getBusinessReason(), e.getEventTimestamp(),
                e.getRecordedAt(), e.getPayload(), e.getPreviousHash(), e.getContentHash(), false);
    }

    static VerifiableEvent of(AuditEventArchiveEntity e) {
        return new VerifiableEvent(e.getSequenceNumber(), e.getEventId(), e.getSchemaVersion(),
                e.getActorId(), e.getActorType(), e.getAction(), e.getResourceType(),
                e.getResourceId(), e.getOutcome(), e.getBusinessReason(), e.getEventTimestamp(),
                e.getRecordedAt(), e.getPayload(), e.getPreviousHash(), e.getContentHash(), true);
    }
}
