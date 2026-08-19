package com.raghavendra.audit.event;

import com.raghavendra.audit.event.api.ApiError;
import com.raghavendra.audit.event.api.AuditExceptionHandler;
import com.raghavendra.audit.event.application.DuplicateEventIdException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for the exception-to-status mapping. Confirms that BOTH the early defensive
 * pre-check exception AND the authoritative database unique-constraint violation map to 409,
 * so a concurrent uniqueness violation can never escape as an undocumented 500.
 */
class AuditExceptionHandlerTest {

    private final AuditExceptionHandler handler = new AuditExceptionHandler();

    @Test
    void duplicateEventIdException_mapsTo409() {
        ResponseEntity<ApiError> resp = handler.handleDuplicate(
                new DuplicateEventIdException(UUID.randomUUID()));
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(resp.getBody()).isNotNull();
        assertThat(resp.getBody().status()).isEqualTo(409);
    }

    @Test
    void dataIntegrityViolation_fromUniqueConstraint_mapsTo409_not500() {
        ResponseEntity<ApiError> resp = handler.handleDuplicate(
                new DataIntegrityViolationException("duplicate key value violates unique constraint"));
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(resp.getBody()).isNotNull();
        assertThat(resp.getBody().status()).isEqualTo(409);
    }
}
