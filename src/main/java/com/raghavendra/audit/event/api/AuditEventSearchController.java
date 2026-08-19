package com.raghavendra.audit.event.api;

import com.raghavendra.audit.event.application.AuditEventQueryService;
import com.raghavendra.audit.event.application.EventPage;
import com.raghavendra.audit.event.application.EventSearchCriteria;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Read API: filtered, cursor-paginated search over audit events.
 *
 * <p>{@code GET /api/v1/audit/events} with any combination of filters
 * ({@code actorId}, {@code resourceType}+{@code resourceId}, {@code eventType},
 * {@code from}/{@code to}) plus {@code cursor} and {@code limit} for pagination. Results are
 * ordered by {@code sequenceNumber} ascending; {@code nextCursor} in the response drives the
 * next page (present only when another page exists, proven by a limit + 1 probe).
 *
 * <p>Parameter semantics:
 * <ul>
 *   <li>{@code cursor} → returns events with {@code sequenceNumber > cursor};</li>
 *   <li>{@code eventType} → filters the stored {@code action} column;</li>
 *   <li>{@code from} inclusive, {@code to} exclusive; {@code from} must be strictly before
 *       {@code to} (else 400);</li>
 *   <li>{@code limit} → defaults to {@value #DEFAULT_LIMIT} when omitted; an explicit value
 *       {@code <= 0} is rejected with 400; values above the service max are clamped.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/audit/events")
public class AuditEventSearchController {

    /** Default page size applied when no {@code limit} is supplied. */
    public static final int DEFAULT_LIMIT = 50;

    private final AuditEventQueryService queryService;

    public AuditEventSearchController(AuditEventQueryService queryService) {
        this.queryService = queryService;
    }

    @GetMapping
    public ResponseEntity<EventPageResponse> search(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime to,
            @RequestParam(required = false) Long cursor,
            @RequestParam(required = false) Integer limit) {

        // Validate limit: absent → default; explicit non-positive → 400.
        int effectiveLimit;
        if (limit == null) {
            effectiveLimit = DEFAULT_LIMIT;
        } else if (limit <= 0) {
            throw new InvalidSearchRequestException("limit must be a positive integer");
        } else {
            effectiveLimit = limit;
        }

        // Validate time range: from must be strictly before to when both are present.
        if (from != null && to != null && !from.isBefore(to)) {
            throw new InvalidSearchRequestException("'from' must be earlier than 'to'");
        }

        // Reflect the actual applied page size (after the service's MAX_LIMIT clamp) in the response.
        int appliedLimit = Math.min(effectiveLimit, AuditEventQueryService.MAX_LIMIT);
        EventSearchCriteria criteria = new EventSearchCriteria(
                actorId, resourceType, resourceId, eventType, from, to, cursor, appliedLimit);

        EventPage page = queryService.search(criteria);
        List<EventView> views = page.events().stream().map(EventView::from).toList();

        // nextCursor: the last returned event's sequence, but ONLY when another page exists.
        Long nextCursor = (page.hasMore() && !page.events().isEmpty())
                ? page.events().get(page.events().size() - 1).getSequenceNumber()
                : null;

        return ResponseEntity.ok(new EventPageResponse(views, nextCursor, appliedLimit));
    }
}
