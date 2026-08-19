package com.raghavendra.audit.event.api;

import com.raghavendra.audit.event.application.DuplicateEventIdException;
import com.raghavendra.audit.redaction.RedactionException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

/**
 * Central exception handling for the write API. Maps domain and validation failures to clean
 * HTTP responses with a structured {@link ApiError} body.
 */
@RestControllerAdvice
public class AuditExceptionHandler {

    /** Bean Validation failures on the request body → 400 with field-level details. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex) {
        List<String> details = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .sorted()
                .toList();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ApiError.of(HttpStatus.BAD_REQUEST.value(), "Bad Request",
                        "Request validation failed", details));
    }

    /** Malformed / unreadable JSON body → 400. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ApiError.of(HttpStatus.BAD_REQUEST.value(), "Bad Request",
                        "Malformed request body", List.of()));
    }

    /** Invalid search query parameters (limit, time range) → 400. */
    @ExceptionHandler(InvalidSearchRequestException.class)
    public ResponseEntity<ApiError> handleInvalidSearch(InvalidSearchRequestException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ApiError.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", ex.getMessage(), List.of()));
    }

    /** Redaction failures → 404 (unknown target) or 400 (invalid/already-redacted field). */
    @ExceptionHandler(RedactionException.class)
    public ResponseEntity<ApiError> handleRedaction(RedactionException ex) {
        HttpStatus status = ex.isNotFound() ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(
                ApiError.of(status.value(), status.getReasonPhrase(), ex.getMessage(), List.of()));
    }

    /**
     * Duplicate event id → 409 Conflict.
     *
     * <p>Two paths reach here, both mapped to 409:
     * <ul>
     *   <li>{@link DuplicateEventIdException} — thrown by the early defensive pre-check;</li>
     *   <li>{@link DataIntegrityViolationException} — the AUTHORITATIVE unique-constraint
     *       violation from the database. The pre-check narrows the window but does not close
     *       the race, so a concurrent insert of the same id must still surface as 409, never
     *       as an undocumented 500.</li>
     * </ul>
     * This guards against an extremely unlikely generated-UUID collision or internal
     * duplicate — not a normal client retry (clients cannot supply eventId).
     */
    @ExceptionHandler({DuplicateEventIdException.class, DataIntegrityViolationException.class})
    public ResponseEntity<ApiError> handleDuplicate(RuntimeException ex) {
        String message = (ex instanceof DuplicateEventIdException)
                ? ex.getMessage()
                : "An audit event with the same identifier already exists";
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                ApiError.of(HttpStatus.CONFLICT.value(), "Conflict", message, List.of()));
    }
}
