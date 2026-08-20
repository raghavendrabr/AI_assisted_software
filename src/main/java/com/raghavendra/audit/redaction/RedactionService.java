package com.raghavendra.audit.redaction;

import com.raghavendra.audit.amendment.domain.AuditAmendmentEntity;
import com.raghavendra.audit.amendment.domain.AuditAmendmentRepository;
import com.raghavendra.audit.common.hash.ProtectedAmendmentProjection;
import com.raghavendra.audit.common.hash.Sha256Hasher;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.retention.domain.AuditEventArchiveEntity;
import com.raghavendra.audit.retention.domain.AuditEventArchiveRepository;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Redacts a declared-redactable payload field on an existing event, backed by an immutable
 * amendment.
 *
 * <p>The operation is a SINGLE transaction that:
 * <ol>
 *   <li>locks the chain head {@code FOR UPDATE} (serializes amendment appends);</li>
 *   <li>validates the target event exists and the field is a redactable envelope with a
 *       non-null plaintext value (idempotency: re-redacting an already-null field is rejected);</li>
 *   <li>appends a {@code REDACTION} amendment (recording who / when / which field) to the
 *       amendment chain and advances the amendment head;</li>
 *   <li>nulls the field's plaintext {@code value} in the base event's stored payload.</li>
 * </ol>
 * The event {@code content_hash} is untouched because it commits to the field's
 * {salt, commitment}, never the plaintext value — so the event chain stays intact. A null value
 * is only legitimate when a matching REDACTION amendment exists (the verifier enforces this).
 */
@Service
public class RedactionService {

    public static final int SCHEMA_VERSION = 1;

    private final AuditEventRepository eventRepository;
    private final AuditEventArchiveRepository archiveRepository;
    private final AuditAmendmentRepository amendmentRepository;
    private final AuditChainHeadRepository chainHeadRepository;
    private final Sha256Hasher hasher;
    private final Clock clock;
    private final EntityManager entityManager;
    private final com.raghavendra.audit.common.observability.AuditMetrics metrics;
    private final ObjectMapper mapper = new ObjectMapper();

    public RedactionService(AuditEventRepository eventRepository,
                            AuditEventArchiveRepository archiveRepository,
                            AuditAmendmentRepository amendmentRepository,
                            AuditChainHeadRepository chainHeadRepository,
                            Sha256Hasher hasher,
                            Clock clock,
                            EntityManager entityManager,
                            com.raghavendra.audit.common.observability.AuditMetrics metrics) {
        this.eventRepository = eventRepository;
        this.archiveRepository = archiveRepository;
        this.amendmentRepository = amendmentRepository;
        this.chainHeadRepository = chainHeadRepository;
        this.hasher = hasher;
        this.clock = clock;
        this.entityManager = entityManager;
        this.metrics = metrics;
    }

    @Transactional
    public AuditAmendmentEntity redactField(long sequenceNumber, String field, String actorId) {
        try {
            AuditAmendmentEntity amendment = doRedactField(sequenceNumber, field, actorId);
            metrics.incrementAfterCommit(metrics::redactionSuccess); // only after commit
            return amendment;
        } catch (RuntimeException e) {
            metrics.redactionFailure();
            throw e;
        }
    }

    private AuditAmendmentEntity doRedactField(long sequenceNumber, String field, String actorId) {
        // Existence check first (clean 404 without taking the lock for a bad target). Redaction
        // works for ACTIVE and ARCHIVED events, so check both tables.
        boolean inActive = eventRepository.findBySequenceNumber(sequenceNumber).isPresent();
        boolean inArchive = archiveRepository.existsBySequenceNumber(sequenceNumber);
        if (!inActive && !inArchive) {
            throw new RedactionException("No audit event with sequence " + sequenceNumber, true);
        }

        // Acquire the head lock BEFORE validating the field state, so the check-then-redact is
        // atomic: concurrent redactions of the same field serialize here, and only the first
        // sees a non-null value.
        AuditChainHeadEntity head = chainHeadRepository.findAndLockSingleton()
                .orElseThrow(() -> new IllegalStateException("chain head row missing"));

        // Clear the persistence context so the post-lock read observes the WINNER's committed
        // payload (a redaction commits via a native UPDATE the first-level cache can't see).
        entityManager.clear();

        // Read the current payload from whichever table holds the event (archival may have moved
        // it between the pre-lock check and now, but the sequence is stable either way).
        boolean archived = archiveRepository.existsBySequenceNumber(sequenceNumber);
        String storedPayload = archived
                ? archiveRepository.findBySequenceNumber(sequenceNumber)
                    .orElseThrow(() -> new RedactionException("No audit event with sequence " + sequenceNumber, true))
                    .getPayload()
                : eventRepository.findBySequenceNumber(sequenceNumber)
                    .orElseThrow(() -> new RedactionException("No audit event with sequence " + sequenceNumber, true))
                    .getPayload();

        ObjectNode payload = parsePayload(storedPayload);
        JsonNode fieldNode = payload.get(field);
        if (!isRedactableEnvelope(fieldNode)) {
            throw new RedactionException(
                    "Field '" + field + "' is not a declared redactable field on this event", false);
        }
        ObjectNode envelope = (ObjectNode) fieldNode;
        JsonNode value = envelope.get("value");
        if (value == null || value.isNull()) {
            throw new RedactionException(
                    "Field '" + field + "' is already redacted", false);
        }

        long nextSeq = head.getLastAmendmentSeq() + 1;
        byte[] prevHash = head.getAmendmentHeadHash(); // null for the first amendment
        OffsetDateTime recordedAt = OffsetDateTime.now(clock)
                .withOffsetSameInstant(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
        UUID amendmentId = UUID.randomUUID();

        ObjectNode detail = mapper.createObjectNode();
        detail.put("field", field);
        String detailJson = detail.toString();

        ProtectedAmendmentProjection projection = new ProtectedAmendmentProjection(
                SCHEMA_VERSION, nextSeq, amendmentId.toString(), "REDACTION",
                sequenceNumber, detailJson, actorId, recordedAt, prevHash);
        byte[] contentHash = hasher.amendmentContentHash(projection);

        AuditAmendmentEntity amendment = new AuditAmendmentEntity(
                amendmentId, nextSeq, "REDACTION", sequenceNumber, detailJson, actorId,
                recordedAt, SCHEMA_VERSION, prevHash, contentHash);
        AuditAmendmentEntity saved = amendmentRepository.save(amendment);

        head.advanceAmendment(nextSeq, contentHash, recordedAt);
        chainHeadRepository.save(head);

        // Null the plaintext value (only permitted base-event mutation), keeping salt+commitment.
        // Write to whichever table currently holds the event (active or archive).
        envelope.set("value", mapper.nullNode());
        if (archived) {
            archiveRepository.updatePayloadBySequence(sequenceNumber, payload.toString());
        } else {
            eventRepository.updatePayloadBySequence(sequenceNumber, payload.toString());
        }

        return saved;
    }

    private ObjectNode parsePayload(String json) {
        if (json == null || json.isBlank()) {
            return mapper.createObjectNode();
        }
        JsonNode n = mapper.readTree(json);
        return n.isObject() ? (ObjectNode) n : mapper.createObjectNode();
    }

    private boolean isRedactableEnvelope(JsonNode n) {
        return n != null && n.isObject() && n.has("salt") && n.has("commitment") && n.has("value");
    }
}
