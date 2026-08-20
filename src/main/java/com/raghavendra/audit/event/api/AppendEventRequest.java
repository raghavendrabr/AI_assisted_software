package com.raghavendra.audit.event.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Request body for {@code POST /api/v1/audit/events}.
 *
 * <p>Bean Validation enforces required fields and length bounds (aligned with the V1 schema
 * column sizes). {@code eventTimestamp} is caller-supplied business time (optional; the server
 * fills it with the ingestion time when absent). The server always assigns {@code eventId},
 * {@code recordedAt}, {@code sequenceNumber}, and the hashes — those are never accepted from
 * the caller.
 *
 * <p><strong>No client idempotency key.</strong> There is intentionally no {@code eventId}
 * field: clients cannot supply or reuse an id, so {@code POST} is <em>not</em> idempotent — a
 * retried request creates a new event. Client-controlled idempotency keys are deferred and
 * would be added explicitly if required.
 *
 * @param eventType      what happened (maps to the {@code action} column)
 * @param actorId        who/what caused the event
 * @param actorType      classifier for the actor
 * @param resourceType   type of affected resource
 * @param resourceId     specific affected resource
 * @param outcome        result of the action (e.g. SUCCESS, DENIED)
 * @param businessReason optional justification
 * @param payload          structured, event-specific detail (JSON object); optional
 * @param redactableFields top-level payload field names to store as redactable envelopes
 *                         (salt + commitment); optional. Only these fields can later be redacted.
 *                         Bounded in count and per-element length/syntax so a request cannot
 *                         declare an unbounded or malformed set of redactable paths. The bounds
 *                         mirror the {@code audit.limits.max-redactable-fields} /
 *                         {@code max-redactable-field-path-length} defaults (64 / 128); the syntax
 *                         restricts each entry to a single top-level identifier
 *                         ({@code [A-Za-z0-9_.-]}), which is all the redaction model supports.
 * @param eventTimestamp   optional caller-supplied business time; defaults to ingestion time
 */
public record AppendEventRequest(
        @NotBlank @Size(max = 128) String eventType,
        @NotBlank @Size(max = 255) String actorId,
        @NotBlank @Size(max = 64) String actorType,
        @NotBlank @Size(max = 128) String resourceType,
        @NotBlank @Size(max = 255) String resourceId,
        @NotBlank @Size(max = 64) String outcome,
        @Size(max = 1024) String businessReason,
        JsonNode payload,
        @Size(max = 64, message = "must not contain more than 64 entries")
        List<
                @NotBlank
                @Size(max = 128, message = "field path must not exceed 128 characters")
                @Pattern(regexp = "[A-Za-z0-9_.\\-]+",
                        message = "field path may contain only letters, digits, '_', '.' or '-'")
                String> redactableFields,
        OffsetDateTime eventTimestamp
) {
}
