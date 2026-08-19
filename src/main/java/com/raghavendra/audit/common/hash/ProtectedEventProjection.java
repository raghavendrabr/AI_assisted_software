package com.raghavendra.audit.common.hash;

import java.time.OffsetDateTime;
import java.util.Objects;

/**
 * The <strong>protected hash projection</strong> of an audit event: the exact, ordered set
 * of fields that the content hash commits to.
 *
 * <p>This is deliberately a small, explicit value object rather than the future JPA entity,
 * so that "what the hash covers" is a single, reviewable, stable contract — independent of
 * how records are stored, transported, or presented. Only these fields, in this order,
 * participate in {@code content_hash}. Anything not present here is, by definition, NOT
 * integrity-protected.
 *
 * <p><strong>Included (protected) fields, in canonical order:</strong>
 * <ol>
 *   <li>{@code schemaVersion} — versions the canonicalization/hash scheme itself</li>
 *   <li>{@code sequenceNumber} — chain position</li>
 *   <li>{@code eventId} — public identifier</li>
 *   <li>{@code actorId}, {@code actorType}</li>
 *   <li>{@code action}</li>
 *   <li>{@code resourceType}, {@code resourceId}</li>
 *   <li>{@code outcome}</li>
 *   <li>{@code businessReason} — nullable</li>
 *   <li>{@code eventTimestamp} — business time, normalized to UTC</li>
 *   <li>{@code recordedAt} — ingestion time, normalized to UTC</li>
 *   <li>{@code payloadJson} — the raw JSON payload, canonicalized (keys sorted) by the serializer</li>
 *   <li>{@code previousHash} — hex of the preceding record's content hash, or null for genesis</li>
 * </ol>
 *
 * <p><strong>Deliberately EXCLUDED from the hash</strong> (documented so the boundary is
 * explicit): the internal surrogate {@code id} (storage-only), and any future mutable
 * lifecycle state (redaction/archival status) — lifecycle changes are recorded as separate
 * hash-chained amendments in later steps, never by mutating this projection.
 *
 * @param schemaVersion  canonicalization/hash scheme version (>0)
 * @param sequenceNumber chain position (>0)
 * @param eventId        public event UUID (as its canonical string form)
 * @param actorId        who/what caused the event
 * @param actorType      classifier for the actor
 * @param action         what happened
 * @param resourceType   type of affected resource
 * @param resourceId     specific affected resource
 * @param outcome        result of the action
 * @param businessReason optional justification (nullable)
 * @param eventTimestamp business occurrence time (nullable; UTC-normalized and truncated to
 *                       microseconds by the serializer to match PostgreSQL TIMESTAMPTZ)
 * @param recordedAt     server ingestion time (nullable; same normalization as eventTimestamp)
 * @param payloadJson    raw JSON payload text; re-canonicalized (object keys sorted) by the serializer
 * @param previousHash   the preceding record's 32-byte content hash, or {@code null} for the
 *                       genesis record (sequence 1). The serializer renders it as exactly
 *                       64 lowercase hex characters; null renders as the JSON {@code null} token.
 */
public record ProtectedEventProjection(
        int schemaVersion,
        long sequenceNumber,
        String eventId,
        String actorId,
        String actorType,
        String action,
        String resourceType,
        String resourceId,
        String outcome,
        String businessReason,
        OffsetDateTime eventTimestamp,
        OffsetDateTime recordedAt,
        String payloadJson,
        byte[] previousHash
) {
    public ProtectedEventProjection {
        // Required (non-null) protected fields. businessReason, timestamps, payloadJson,
        // and previousHash may legitimately be null (documented null handling).
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(actorId, "actorId");
        Objects.requireNonNull(actorType, "actorType");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(resourceType, "resourceType");
        Objects.requireNonNull(resourceId, "resourceId");
        Objects.requireNonNull(outcome, "outcome");
        // previousHash, when present, must be exactly a 32-byte SHA-256 (matches V1 schema).
        if (previousHash != null && previousHash.length != 32) {
            throw new IllegalArgumentException(
                    "previousHash must be null (genesis) or exactly 32 bytes, was " + previousHash.length);
        }
        // Genesis rule mirrors the DB CHECK: sequence 1 => no previousHash; sequence > 1 => previousHash present.
        if (sequenceNumber == 1 && previousHash != null) {
            throw new IllegalArgumentException("genesis event (sequence 1) must have null previousHash");
        }
        if (sequenceNumber > 1 && previousHash == null) {
            throw new IllegalArgumentException("non-genesis event (sequence > 1) requires a previousHash");
        }
        // Defensive copy on construction: the projection must not alias the caller's array,
        // so later mutation of the caller's original cannot alter this projection's hash input.
        previousHash = (previousHash == null) ? null : previousHash.clone();
    }

    /**
     * Returns a defensive copy of the previous record's content hash (32 bytes), or
     * {@code null} for the genesis record. The internal array is never exposed directly, so
     * callers cannot mutate the projection's integrity-relevant state through the accessor.
     */
    @Override
    public byte[] previousHash() {
        return (previousHash == null) ? null : previousHash.clone();
    }
}
