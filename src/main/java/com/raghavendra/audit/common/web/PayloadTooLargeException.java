package com.raghavendra.audit.common.web;

/**
 * Raised when a request body exceeds the configured byte limit
 * ({@code audit.limits.max-request-bytes}). Mapped to HTTP 413 with a safe, generic body that
 * never echoes any of the received bytes.
 */
public class PayloadTooLargeException extends RuntimeException {
    public PayloadTooLargeException(String message) {
        super(message);
    }
}
