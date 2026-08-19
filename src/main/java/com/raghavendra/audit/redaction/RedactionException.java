package com.raghavendra.audit.redaction;

/**
 * Thrown when a redaction request cannot be satisfied: unknown target event (→ 404), or a field
 * that is not a declared redactable field / already redacted (→ 400/409). The {@code notFound}
 * flag lets the handler choose the status.
 */
public class RedactionException extends RuntimeException {

    private final boolean notFound;

    public RedactionException(String message, boolean notFound) {
        super(message);
        this.notFound = notFound;
    }

    public boolean isNotFound() {
        return notFound;
    }
}
