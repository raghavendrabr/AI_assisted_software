package com.raghavendra.audit.event.application;

import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.retention.domain.AuditEventArchiveEntity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Source-agnostic read row for an event, so search/compliance can present active and archived
 * events uniformly. {@code archived} tells the caller where the row currently lives.
 */
public record EventRow(
        UUID eventId,
        long sequenceNumber,
        String eventType,
        String actorId,
        String actorType,
        String resourceType,
        String resourceId,
        String outcome,
        String businessReason,
        OffsetDateTime eventTimestamp,
        OffsetDateTime recordedAt,
        int schemaVersion,
        String payload,
        byte[] previousHash,
        byte[] contentHash,
        boolean archived
) {
    public static EventRow of(AuditEventEntity e) {
        return new EventRow(e.getEventId(), e.getSequenceNumber(), e.getAction(), e.getActorId(),
                e.getActorType(), e.getResourceType(), e.getResourceId(), e.getOutcome(),
                e.getBusinessReason(), e.getEventTimestamp(), e.getRecordedAt(), e.getSchemaVersion(),
                e.getPayload(), e.getPreviousHash(), e.getContentHash(), false);
    }

    public static EventRow of(AuditEventArchiveEntity e) {
        return new EventRow(e.getEventId(), e.getSequenceNumber(), e.getAction(), e.getActorId(),
                e.getActorType(), e.getResourceType(), e.getResourceId(), e.getOutcome(),
                e.getBusinessReason(), e.getEventTimestamp(), e.getRecordedAt(), e.getSchemaVersion(),
                e.getPayload(), e.getPreviousHash(), e.getContentHash(), true);
    }
}
