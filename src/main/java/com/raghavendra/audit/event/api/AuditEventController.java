package com.raghavendra.audit.event.api;

import com.raghavendra.audit.event.application.AuditEventAppendService;
import com.raghavendra.audit.event.domain.AuditEventEntity;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.UUID;

/**
 * Write API for the audit log.
 *
 * <p>Append-only by design: this controller exposes only {@code POST} (create). There is no
 * update or delete endpoint, in line with the tamper-evidence requirement.
 */
@RestController
@RequestMapping("/api/v1/audit/events")
public class AuditEventController {

    private final AuditEventAppendService appendService;

    public AuditEventController(AuditEventAppendService appendService) {
        this.appendService = appendService;
    }

    /**
     * Append a new audit event. The server assigns the id, sequence, timestamps, and hashes.
     * Returns 201 Created with the server-assigned identity and chain metadata.
     */
    @PostMapping
    public ResponseEntity<AppendEventResponse> append(
            @Valid @RequestBody AppendEventRequest request,
            UriComponentsBuilder uriBuilder) {

        UUID eventId = UUID.randomUUID(); // server-assigned public id
        AuditEventEntity saved = appendService.append(request, eventId);

        URI location = uriBuilder.path("/api/v1/audit/events/{eventId}")
                .buildAndExpand(saved.getEventId())
                .toUri();

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .location(location)
                .body(AppendEventResponse.from(saved));
    }
}
