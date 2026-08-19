package com.raghavendra.audit.event.api;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Structured error response body. {@code details} carries field-level validation messages
 * when present.
 */
public record ApiError(
        OffsetDateTime timestamp,
        int status,
        String error,
        String message,
        List<String> details
) {
    public static ApiError of(int status, String error, String message, List<String> details) {
        return new ApiError(OffsetDateTime.now(), status, error, message,
                details == null ? List.of() : details);
    }
}
