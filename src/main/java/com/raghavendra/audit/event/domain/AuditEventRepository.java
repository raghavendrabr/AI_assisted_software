package com.raghavendra.audit.event.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

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

    /** All events ordered by chain position — used by the verifier. */
    List<AuditEventEntity> findAllByOrderBySequenceNumberAsc();
}
