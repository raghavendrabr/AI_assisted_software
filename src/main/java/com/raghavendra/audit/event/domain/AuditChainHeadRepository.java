package com.raghavendra.audit.event.domain;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

/**
 * Repository for the singleton {@code audit_chain_head} row.
 *
 * <p>{@link #findAndLockSingleton()} issues {@code SELECT ... FOR UPDATE} (via
 * {@link LockModeType#PESSIMISTIC_WRITE}) so concurrent appends serialize on the head row,
 * guaranteeing a single deterministic chain.
 */
public interface AuditChainHeadRepository extends JpaRepository<AuditChainHeadEntity, Short> {

    /**
     * Load the singleton head row with a pessimistic write lock (SELECT ... FOR UPDATE).
     * All appends acquire this lock first, so only one append proceeds at a time.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select h from AuditChainHeadEntity h where h.id = 1")
    Optional<AuditChainHeadEntity> findAndLockSingleton();
}
