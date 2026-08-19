package com.raghavendra.audit.event.api;

/**
 * Thrown when search query parameters are invalid (e.g. non-positive limit, or
 * {@code from} not earlier than {@code to}). Maps to HTTP 400.
 */
public class InvalidSearchRequestException extends RuntimeException {

    public InvalidSearchRequestException(String message) {
        super(message);
    }
}
