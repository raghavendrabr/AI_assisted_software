package com.raghavendra.audit.event.api;

import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.common.hash.HexFormatUtil;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Response body returned after a successful append.
 *
 * <p>Echoes the server-assigned identity and chain metadata so the caller can confirm the
 * record's position and integrity fields. Hashes are rendered as lowercase hex.
 */
public record AppendEventResponse(
        UUID eventId,
        long sequenceNumber,
        OffsetDateTime eventTimestamp,
        OffsetDateTime recordedAt,
        int schemaVersion,
        String previousHash,
        String contentHash
) {
    public static AppendEventResponse from(AuditEventEntity e) {
        return new AppendEventResponse(
                e.getEventId(),
                e.getSequenceNumber(),
                e.getEventTimestamp(),
                e.getRecordedAt(),
                e.getSchemaVersion(),
                e.getPreviousHash() == null ? null : HexFormatUtil.toLowerHex(e.getPreviousHash()),
                HexFormatUtil.toLowerHex(e.getContentHash())
        );
    }
}
