package com.raghavendra.audit.event.application;

import java.util.List;

/**
 * Internal paginated result of a search.
 *
 * @param events  the rows to return (at most the requested limit), source-agnostic
 * @param hasMore whether a further page exists (proven by fetching limit + 1 rows)
 */
public record EventPage(List<EventRow> events, boolean hasMore) {
}
