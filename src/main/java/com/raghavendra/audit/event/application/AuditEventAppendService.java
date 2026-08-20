package com.raghavendra.audit.event.application;

import com.raghavendra.audit.common.hash.CanonicalJsonSerializer;
import com.raghavendra.audit.common.hash.ProtectedEventProjection;
import com.raghavendra.audit.common.hash.Sha256Hasher;
import com.raghavendra.audit.common.observability.AuditMetrics;
import com.raghavendra.audit.redaction.RedactablePayloadProcessor;
import com.raghavendra.audit.event.api.AppendEventRequest;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Appends a new event to the tamper-evident chain.
 *
 * <p><strong>Concurrency &amp; ordering.</strong> Each append runs in a single transaction that
 * first locks the singleton {@code audit_chain_head} row with {@code SELECT ... FOR UPDATE}
 * (see {@link AuditChainHeadRepository#findAndLockSingleton()}). This serializes concurrent
 * appends into one deterministic chain: sequence numbers are strictly increasing with no gaps,
 * and each record's {@code previous_hash} is exactly the prior record's {@code content_hash}.
 *
 * <p><strong>Server-assigned fields.</strong> The caller may supply the business
 * {@code eventTimestamp}; the server always assigns {@code recordedAt}, {@code sequenceNumber},
 * {@code previousHash}, and {@code contentHash}. Both timestamps are normalized to UTC and
 * truncated to microseconds — the SAME normalized values are hashed AND persisted, so the
 * stored record re-verifies after a reread (ADR 0003).
 */
@Service
public class AuditEventAppendService {

    /** Current canonicalization/hash scheme version (ADR 0003). */
    public static final int SCHEMA_VERSION = 1;

    private final AuditEventRepository eventRepository;
    private final AuditChainHeadRepository chainHeadRepository;
    private final CanonicalJsonSerializer serializer;
    private final Sha256Hasher hasher;
    private final RedactablePayloadProcessor payloadProcessor;
    private final Clock clock;
    private final AuditMetrics metrics;

    public AuditEventAppendService(
            AuditEventRepository eventRepository,
            AuditChainHeadRepository chainHeadRepository,
            CanonicalJsonSerializer serializer,
            Sha256Hasher hasher,
            RedactablePayloadProcessor payloadProcessor,
            Clock clock,
            AuditMetrics metrics) {
        this.eventRepository = eventRepository;
        this.chainHeadRepository = chainHeadRepository;
        this.serializer = serializer;
        this.hasher = hasher;
        this.payloadProcessor = payloadProcessor;
        this.clock = clock;
        this.metrics = metrics;
    }

    /**
     * Append an event. Runs in a single transaction; on any failure the whole append rolls
     * back (no partial event, no head advance).
     *
     * @throws DuplicateEventIdException if the supplied eventId already exists (HTTP 409)
     */
    @Transactional
    public AuditEventEntity append(AppendEventRequest request, UUID eventId) {
        try {
            AuditEventEntity saved = doAppend(request, eventId);
            // Success is counted ONLY after the transaction commits (never on rollback).
            metrics.incrementAfterCommit(metrics::appendedSuccess);
            return saved;
        } catch (RuntimeException e) {
            // A failed/rolled-back append: count failure, not success.
            metrics.appendFailure();
            throw e;
        }
    }

    private AuditEventEntity doAppend(AppendEventRequest request, UUID eventId) {
        // EARLY DEFENSIVE pre-check only. The authoritative guarantee is the UNIQUE constraint
        // on event_id in the database; this pre-check just turns the common case into a clean
        // 409 without a DB round-trip failure. It does NOT close the race between check and
        // insert — a concurrent insert of the same id is caught by the unique constraint and
        // translated to 409 by AuditExceptionHandler (DataIntegrityViolationException), never
        // surfaced as a 500. Note: eventId is server-generated, so this protects against an
        // extremely unlikely UUID collision / internal duplicate, not a normal client retry.
        if (eventRepository.existsByEventId(eventId)) {
            throw new DuplicateEventIdException(eventId);
        }

        // Lock the chain head FOR UPDATE — serializes all concurrent appends.
        AuditChainHeadEntity head = chainHeadRepository.findAndLockSingleton()
                .orElseThrow(() -> new IllegalStateException(
                        "audit_chain_head singleton row is missing; V1 migration seeds it"));

        long nextSequence = head.getCurrentSequence() + 1;
        byte[] previousHash = head.getCurrentHash(); // null when chain is empty (genesis)

        // Normalize timestamps: UTC + truncate to microseconds. These EXACT values are both
        // hashed and persisted.
        OffsetDateTime now = OffsetDateTime.now(clock);
        OffsetDateTime recordedAt = normalize(now);
        OffsetDateTime eventTimestamp = request.eventTimestamp() != null
                ? normalize(request.eventTimestamp())
                : recordedAt;

        // Process redactable fields: `stored` keeps plaintext (until redacted); `forHash`
        // commits to salt+commitment only, so a later redaction (nulling the value) leaves the
        // content hash unchanged. Non-redactable fields are identical in both.
        RedactablePayloadProcessor.Processed processed =
                payloadProcessor.process(eventId.toString(), request.payload(), request.redactableFields());
        String storedPayloadJson = processed.storedPayloadJson();
        String hashPayloadJson = processed.hashPayloadJson();

        ProtectedEventProjection projection = new ProtectedEventProjection(
                SCHEMA_VERSION,
                nextSequence,
                eventId.toString(),
                request.actorId(),
                request.actorType(),
                request.eventType(),
                request.resourceType(),
                request.resourceId(),
                request.outcome(),
                request.businessReason(),
                eventTimestamp,
                recordedAt,
                hashPayloadJson, // hash commits to the redaction-stable payload projection
                previousHash
        );

        byte[] contentHash = hasher.contentHash(projection);

        AuditEventEntity entity = new AuditEventEntity(
                eventId, nextSequence, request.actorId(), request.actorType(), request.eventType(),
                request.resourceType(), request.resourceId(), request.outcome(),
                request.businessReason(), eventTimestamp, recordedAt, SCHEMA_VERSION,
                storedPayloadJson, previousHash, contentHash); // store full payload (with values)

        AuditEventEntity saved = eventRepository.save(entity);

        // Advance the locked head to the new tip. Committed atomically with the event insert.
        head.advanceTo(nextSequence, contentHash, recordedAt);
        chainHeadRepository.save(head);

        return saved;
    }

    private OffsetDateTime normalize(OffsetDateTime ts) {
        return ts.withOffsetSameInstant(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
    }
}
