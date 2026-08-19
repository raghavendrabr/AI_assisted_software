package com.raghavendra.audit.event.application;

import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.retention.domain.AuditEventArchiveEntity;
import com.raghavendra.audit.retention.domain.AuditEventArchiveRepository;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Read-only, bounded, cursor-paginated search over audit events.
 *
 * <p>Ordering is always by {@code sequenceNumber} ascending — a monotonic, insert-stable key —
 * so cursor pagination ({@code afterSequence}) is stable under concurrent inserts. Page size is
 * clamped to {@link #MAX_LIMIT}; the fetch uses limit + 1 to report {@code hasMore}.
 *
 * <p><strong>Archived events:</strong> by default the search returns only ACTIVE events. When
 * {@code includeArchived} is true, archived events (moved to {@code audit_event_archive} by
 * retention) are merged into the results and ordered together by sequence — so a report can span
 * the full history. This is a documented, explicit behavior (default false), not silent omission.
 *
 * <p>{@code eventType} filters the stored {@code action} column.
 */
@Service
public class AuditEventQueryService {

    public static final int MAX_LIMIT = 200;

    private final AuditEventRepository repository;
    private final AuditEventArchiveRepository archiveRepository;

    public AuditEventQueryService(AuditEventRepository repository,
                                  AuditEventArchiveRepository archiveRepository) {
        this.repository = repository;
        this.archiveRepository = archiveRepository;
    }

    @Transactional(readOnly = true)
    public EventPage search(EventSearchCriteria c) {
        int limit = Math.min(c.limit(), MAX_LIMIT);
        PageRequest page = PageRequest.of(0, limit + 1, Sort.by(Sort.Direction.ASC, "sequenceNumber"));

        List<EventRow> rows = new ArrayList<>();
        repository.findAll(this.<AuditEventEntity>spec(c), page).forEach(e -> rows.add(EventRow.of(e)));

        if (c.includeArchived()) {
            archiveRepository.findAll(this.<AuditEventArchiveEntity>spec(c), page)
                    .forEach(e -> rows.add(EventRow.of(e)));
            rows.sort(Comparator.comparingLong(EventRow::sequenceNumber));
        }

        boolean hasMore = rows.size() > limit;
        List<EventRow> events = hasMore ? new ArrayList<>(rows.subList(0, limit)) : rows;
        return new EventPage(events, hasMore);
    }

    /** Builds the filter specification generically for either the active or archive entity. */
    private <T> Specification<T> spec(EventSearchCriteria c) {
        return (root, query, cb) -> {
            List<Predicate> ps = new ArrayList<>();
            if (c.actorId() != null) {
                ps.add(cb.equal(root.get("actorId"), c.actorId()));
            }
            if (c.resourceType() != null) {
                ps.add(cb.equal(root.get("resourceType"), c.resourceType()));
            }
            if (c.resourceId() != null) {
                ps.add(cb.equal(root.get("resourceId"), c.resourceId()));
            }
            if (c.eventType() != null) {
                ps.add(cb.equal(root.get("action"), c.eventType()));
            }
            if (c.outcome() != null) {
                ps.add(cb.equal(root.get("outcome"), c.outcome()));
            }
            if (c.from() != null) {
                Path<java.time.OffsetDateTime> ts = root.get("eventTimestamp");
                ps.add(cb.greaterThanOrEqualTo(ts, c.from()));
            }
            if (c.to() != null) {
                Path<java.time.OffsetDateTime> ts = root.get("eventTimestamp");
                ps.add(cb.lessThan(ts, c.to()));
            }
            if (c.afterSequence() != null) {
                Path<Long> seq = root.get("sequenceNumber");
                ps.add(cb.greaterThan(seq, c.afterSequence()));
            }
            return cb.and(ps.toArray(new Predicate[0]));
        };
    }
}
