package com.raghavendra.audit.retention.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Repository for archived events. Insert + read + (redaction-only) payload update. */
public interface AuditEventArchiveRepository
        extends JpaRepository<AuditEventArchiveEntity, Long>, JpaSpecificationExecutor<AuditEventArchiveEntity> {

    List<AuditEventArchiveEntity> findAllByOrderBySequenceNumberAsc();

    Optional<AuditEventArchiveEntity> findBySequenceNumber(Long sequenceNumber);

    Optional<AuditEventArchiveEntity> findByEventId(UUID eventId);

    boolean existsBySequenceNumber(Long sequenceNumber);

    /** Redaction of an ARCHIVED event: null a redactable field's plaintext (chain-safe). */
    @Modifying
    @Query(value = "UPDATE audit_event_archive SET payload = CAST(:payload AS jsonb) "
            + "WHERE sequence_number = :seq", nativeQuery = true)
    int updatePayloadBySequence(@Param("seq") long sequenceNumber, @Param("payload") String payloadJson);
}
