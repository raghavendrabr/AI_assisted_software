package com.raghavendra.audit.retention;

/** Thrown when an archival request is invalid (e.g. nothing eligible) → 400. */
public class ArchiveException extends RuntimeException {
    public ArchiveException(String message) {
        super(message);
    }
}
