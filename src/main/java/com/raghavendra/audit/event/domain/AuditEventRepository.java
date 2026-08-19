package com.raghavendra.audit.event.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Repository for append-only {@code audit_event} records.
 *
 * <p>Append-only by contract: only {@code save} (insert) is used; no update/delete paths are
 * exposed by the service. Query methods for the read API arrive in a later step.
 */
public interface AuditEventRepository extends JpaRepository<AuditEventEntity, Long> {

    boolean existsByEventId(UUID eventId);

    Optional<AuditEventEntity> findByEventId(UUID eventId);
}
