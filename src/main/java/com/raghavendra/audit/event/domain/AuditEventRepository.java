package com.raghavendra.audit.event.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for append-only {@code audit_event} records.
 *
 * <p>Append-only by contract: only {@code save} (insert) is used; no update/delete paths are
 * exposed by the service. {@link JpaSpecificationExecutor} supports the filtered search API;
 * {@link #findAllByOrderBySequenceNumberAsc()} streams the full chain in order for verification.
 */
public interface AuditEventRepository
        extends JpaRepository<AuditEventEntity, Long>, JpaSpecificationExecutor<AuditEventEntity> {

    boolean existsByEventId(UUID eventId);

    Optional<AuditEventEntity> findByEventId(UUID eventId);

    Optional<AuditEventEntity> findBySequenceNumber(Long sequenceNumber);

    /** All events ordered by chain position — used by the verifier. */
    List<AuditEventEntity> findAllByOrderBySequenceNumberAsc();

    /**
     * Redaction: overwrite the stored payload JSONB for one event. This is the ONLY permitted
     * mutation of a base event, and it only ever nulls a redactable field's plaintext value
     * (which content_hash never covered), so the event chain stays intact. Native update so it
     * bypasses the entity's updatable=false mapping and is applied atomically in the redaction
     * transaction.
     */
    @Modifying
    @Query(value = "UPDATE audit_event SET payload = CAST(:payload AS jsonb) "
            + "WHERE sequence_number = :seq", nativeQuery = true)
    int updatePayloadBySequence(@Param("seq") long sequenceNumber, @Param("payload") String payloadJson);
}
