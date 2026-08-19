package com.raghavendra.audit.event.api;

import java.util.List;

/**
 * Cursor-paginated search response.
 *
 * @param events      the page of events (ordered by sequenceNumber ascending)
 * @param nextCursor  the sequenceNumber to pass as {@code afterSequence} for the next page,
 *                    or {@code null} when this is the last page
 * @param limit       the effective page size applied (after server-side clamping)
 */
public record EventPageResponse(
        List<EventView> events,
        Long nextCursor,
        int limit
) {
}
