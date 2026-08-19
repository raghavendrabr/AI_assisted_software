package com.raghavendra.audit.compliance;

import com.raghavendra.audit.event.api.AuditEventSearchController;
import com.raghavendra.audit.event.api.InvalidSearchRequestException;
import com.raghavendra.audit.event.application.AuditEventQueryService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;

/**
 * Compliance reporting API (Scenario C in-scope slice).
 *
 * <p>{@code GET /api/v1/compliance/access-report} — an immutable, independently-verifiable
 * report of access to client-account data, including BOTH successful and denied access,
 * filterable by {@code actorId}, {@code accountId} (the account resourceId), {@code outcome},
 * and time range ({@code from}/{@code to}). Requires COMPLIANCE_READER or ADMIN.
 */
@RestController
@RequestMapping("/api/v1/compliance/access-report")
public class ComplianceReportController {

    private final ComplianceReportService reportService;

    public ComplianceReportController(ComplianceReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping
    public ResponseEntity<AccessReportResponse> report(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String accountId,
            @RequestParam(required = false) String outcome,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime to,
            @RequestParam(required = false) Long cursor,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false, defaultValue = "true") boolean includeArchived) {

        int effectiveLimit;
        if (limit == null) {
            effectiveLimit = AuditEventSearchController.DEFAULT_LIMIT;
        } else if (limit <= 0) {
            throw new InvalidSearchRequestException("limit must be a positive integer");
        } else {
            effectiveLimit = Math.min(limit, AuditEventQueryService.MAX_LIMIT);
        }

        if (from != null && to != null && !from.isBefore(to)) {
            throw new InvalidSearchRequestException("'from' must be earlier than 'to'");
        }

        return ResponseEntity.ok(reportService.report(
                actorId, accountId, outcome, from, to, cursor, effectiveLimit, includeArchived));
    }
}
