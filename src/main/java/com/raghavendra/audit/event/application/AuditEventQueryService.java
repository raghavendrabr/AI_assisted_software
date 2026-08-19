package com.raghavendra.audit.event.application;

import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/**
 * Read-only, bounded, cursor-paginated search over audit events.
 *
 * <p><strong>Ordering:</strong> always by {@code sequenceNumber} ascending — a monotonic,
 * insert-stable key.
 *
 * <p><strong>Cursor:</strong> {@code afterSequence} means "return rows with
 * {@code sequenceNumber > afterSequence}"; combined with ascending order this yields stable
 * pages even while new events are appended concurrently (offset pagination would shift).
 *
 * <p><strong>Bounded &amp; has-more via limit + 1:</strong> the query fetches at most
 * {@code limit + 1} rows; it returns at most {@code limit} and reports {@code hasMore = true}
 * only when the extra row was present (proving another page exists). The page size is clamped
 * to {@link #MAX_LIMIT}. A non-positive limit is rejected by validation upstream (the
 * controller returns 400), not silently normalized.
 *
 * <p><strong>eventType:</strong> the {@code eventType} filter matches the stored
 * {@code action} column (the write API accepts {@code eventType} and persists it as
 * {@code action}).
 */
@Service
public class AuditEventQueryService {

    /** Hard upper bound on page size, regardless of the requested limit. */
    public static final int MAX_LIMIT = 200;

    private final AuditEventRepository repository;

    public AuditEventQueryService(AuditEventRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public EventPage search(EventSearchCriteria c) {
        int limit = Math.min(c.limit(), MAX_LIMIT); // c.limit() already validated > 0 upstream

        Specification<AuditEventEntity> spec = (root, query, cb) -> {
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
                // eventType filters the stored `action` column.
                ps.add(cb.equal(root.get("action"), c.eventType()));
            }
            if (c.outcome() != null) {
                ps.add(cb.equal(root.get("outcome"), c.outcome()));
            }
            if (c.from() != null) {
                ps.add(cb.greaterThanOrEqualTo(root.get("eventTimestamp"), c.from()));
            }
            if (c.to() != null) {
                ps.add(cb.lessThan(root.get("eventTimestamp"), c.to()));
            }
            if (c.afterSequence() != null) {
                ps.add(cb.greaterThan(root.get("sequenceNumber"), c.afterSequence()));
            }
            return cb.and(ps.toArray(new Predicate[0]));
        };

        // Fetch limit + 1 to detect whether a further page exists.
        PageRequest page = PageRequest.of(0, limit + 1, Sort.by(Sort.Direction.ASC, "sequenceNumber"));
        List<AuditEventEntity> rows = repository.findAll(spec, page).getContent();

        boolean hasMore = rows.size() > limit;
        List<AuditEventEntity> events = hasMore ? rows.subList(0, limit) : rows;
        return new EventPage(events, hasMore);
    }
}
