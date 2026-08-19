package com.raghavendra.audit.amendment.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * Repository for append-only {@code audit_amendment} records. Only inserts are used.
 */
public interface AuditAmendmentRepository extends JpaRepository<AuditAmendmentEntity, Long> {

    /** All amendments ordered by chain position — used by the verifier. */
    List<AuditAmendmentEntity> findAllByOrderByAmendmentSeqAsc();

    /** Amendments targeting a specific base event (any operation). */
    List<AuditAmendmentEntity> findByTargetSequenceNumber(Long targetSequenceNumber);
}
