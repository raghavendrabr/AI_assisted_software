package com.raghavendra.audit.compliance;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Compliance access report response. Carries the report entries plus the filter echo and a
 * cursor for pagination (same limit + 1 semantics as the search API).
 *
 * @param generatedAt when the report was produced (UTC)
 * @param filters     the applied filters (echoed for the record)
 * @param entries     the access entries (ordered by sequenceNumber ascending)
 * @param nextCursor  sequence to pass as {@code cursor} for the next page, or null if last page
 */
public record AccessReportResponse(
        OffsetDateTime generatedAt,
        AppliedFilters filters,
        List<AccessReportEntry> entries,
        Long nextCursor
) {
    public record AppliedFilters(
            String actorId,
            String accountId,
            String outcome,
            OffsetDateTime from,
            OffsetDateTime to,
            String clientAccountResourceType
    ) {
    }
}
