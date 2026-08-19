package com.raghavendra.audit.event.application;

import java.util.UUID;

/**
 * Thrown when an append is attempted with an {@code eventId} that already exists. Maps to
 * HTTP 409 Conflict. Append remains idempotent-safe: a duplicate id is rejected, never
 * silently overwritten (the log is append-only).
 */
public class DuplicateEventIdException extends RuntimeException {

    public DuplicateEventIdException(UUID eventId) {
        super("An audit event with id " + eventId + " already exists");
    }
}
