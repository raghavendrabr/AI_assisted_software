package com.raghavendra.audit.event.application;

import com.raghavendra.audit.event.domain.AuditEventEntity;

import java.util.List;

/**
 * Internal paginated result of a search.
 *
 * @param events  the events to return (at most the requested limit)
 * @param hasMore whether a further page exists (proven by fetching limit + 1 rows)
 */
public record EventPage(List<AuditEventEntity> events, boolean hasMore) {
}
