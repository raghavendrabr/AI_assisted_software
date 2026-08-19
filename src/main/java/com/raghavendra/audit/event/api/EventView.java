package com.raghavendra.audit.event.api;

import com.raghavendra.audit.common.hash.HexFormatUtil;
import com.raghavendra.audit.event.application.EventRow;
import com.raghavendra.audit.event.domain.AuditEventEntity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Read model for an audit event returned by the search API. Hashes are lowercase hex; the raw
 * JSON payload is passed through as text.
 */
public record EventView(
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
        String previousHash,
        String contentHash,
        boolean archived
) {
    public static EventView from(EventRow e) {
        return new EventView(
                e.eventId(),
                e.sequenceNumber(),
                e.eventType(),
                e.actorId(),
                e.actorType(),
                e.resourceType(),
                e.resourceId(),
                e.outcome(),
                e.businessReason(),
                e.eventTimestamp(),
                e.recordedAt(),
                e.schemaVersion(),
                e.payload(),
                e.previousHash() == null ? null : HexFormatUtil.toLowerHex(e.previousHash()),
                HexFormatUtil.toLowerHex(e.contentHash()),
                e.archived()
        );
    }

    public static EventView from(AuditEventEntity e) {
        return from(EventRow.of(e));
    }
}
