package com.raghavendra.audit.compliance;

import com.raghavendra.audit.event.application.AuditEventQueryService;
import com.raghavendra.audit.event.application.EventPage;
import com.raghavendra.audit.event.application.EventSearchCriteria;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Produces the compliance access report (Scenario C in-scope slice): access to client-account
 * data, filterable by actor, account, outcome, and time range.
 *
 * <p>Scoped to events whose {@code resourceType} equals the configured client-account resource
 * type, so the report only ever covers client-account access. Includes BOTH successful and
 * denied access (distinguished by the {@code outcome} field). Reuses the bounded, cursor-
 * paginated query service, so the report inherits stable pagination and the MAX_LIMIT bound.
 */
@Service
public class ComplianceReportService {

    private final AuditEventQueryService queryService;
    private final ComplianceProperties properties;

    public ComplianceReportService(AuditEventQueryService queryService,
                                   ComplianceProperties properties) {
        this.queryService = queryService;
        this.properties = properties;
    }

    public AccessReportResponse report(String actorId, String accountId, String outcome,
                                       OffsetDateTime from, OffsetDateTime to,
                                       Long cursor, int limit, boolean includeArchived) {
        String resourceType = properties.clientAccountResourceType();

        EventSearchCriteria criteria = new EventSearchCriteria(
                actorId, resourceType, accountId, /* eventType */ null, outcome,
                from, to, cursor, limit, includeArchived);

        EventPage page = queryService.search(criteria);
        List<AccessReportEntry> entries = page.events().stream()
                .map(AccessReportEntry::from)
                .toList();

        Long nextCursor = (page.hasMore() && !page.events().isEmpty())
                ? page.events().get(page.events().size() - 1).sequenceNumber()
                : null;

        return new AccessReportResponse(
                OffsetDateTime.now(java.time.ZoneOffset.UTC),
                new AccessReportResponse.AppliedFilters(actorId, accountId, outcome, from, to, resourceType),
                entries,
                nextCursor);
    }
}
