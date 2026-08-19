package com.raghavendra.audit.event.application;

import java.time.OffsetDateTime;

/**
 * Filter criteria for the search API. All fields are optional and combine with AND. Results
 * are ordered by {@code sequenceNumber} ascending and paginated by a cursor over that column.
 *
 * @param actorId      exact actor match
 * @param resourceType exact resource-type match
 * @param resourceId   exact resource-id match
 * @param eventType    exact action/eventType match
 * @param from         inclusive lower bound on eventTimestamp
 * @param to           exclusive upper bound on eventTimestamp
 * @param afterSequence cursor: return only events with sequenceNumber strictly greater
 * @param limit        maximum rows to return (bounded by the service)
 */
public record EventSearchCriteria(
        String actorId,
        String resourceType,
        String resourceId,
        String eventType,
        OffsetDateTime from,
        OffsetDateTime to,
        Long afterSequence,
        int limit
) {
}
