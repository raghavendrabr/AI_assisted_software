package com.raghavendra.audit.compliance;

import com.raghavendra.audit.common.hash.HexFormatUtil;
import com.raghavendra.audit.event.domain.AuditEventEntity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * One entry in a compliance access report: WHO accessed WHICH client account, WHEN, HOW (the
 * action), the business purpose, and WHETHER it succeeded — tied back to the immutable audit
 * record via its sequence number and content hash so the report is independently verifiable.
 */
public record AccessReportEntry(
        UUID eventId,
        long sequenceNumber,
        String actorId,
        String actorType,
        String accountId,       // resourceId of the client account
        String action,          // how the access occurred (eventType)
        String outcome,         // SUCCESS / DENIED / ...
        String businessReason,  // why
        OffsetDateTime accessedAt,   // business time (UTC)
        OffsetDateTime recordedAt,   // ingestion time (UTC)
        String contentHash
) {
    public static AccessReportEntry from(AuditEventEntity e) {
        return new AccessReportEntry(
                e.getEventId(),
                e.getSequenceNumber(),
                e.getActorId(),
                e.getActorType(),
                e.getResourceId(),
                e.getAction(),
                e.getOutcome(),
                e.getBusinessReason(),
                e.getEventTimestamp(),
                e.getRecordedAt(),
                HexFormatUtil.toLowerHex(e.getContentHash())
        );
    }
}
