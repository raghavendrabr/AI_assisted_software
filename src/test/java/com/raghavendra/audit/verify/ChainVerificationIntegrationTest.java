package com.raghavendra.audit.verify;

import com.raghavendra.audit.event.api.AppendEventRequest;
import com.raghavendra.audit.event.application.AuditEventAppendService;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end verification tests: append a valid chain, confirm it verifies, then tamper with a
 * record DIRECTLY in the data store (as an attacker would) and confirm each violation type is
 * detected at the correct record. Runs against real PostgreSQL 16 (Testcontainers).
 */
@SpringBootTest
@AbstractPostgresIntegrationTest.WithPostgres
class ChainVerificationIntegrationTest {

    @Autowired private AuditEventAppendService appendService;
    @Autowired private ChainVerificationService verificationService;
    @Autowired private AuditEventRepository eventRepository;
    @Autowired private AuditChainHeadRepository chainHeadRepository;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private com.raghavendra.audit.amendment.domain.AuditAmendmentRepository amendmentRepository;
    @Autowired private com.raghavendra.audit.retention.domain.ArchiveManifestRepository manifestRepository;
    @Autowired private com.raghavendra.audit.retention.domain.AuditEventArchiveRepository archiveRepository;

    @BeforeEach
    void reset() {
        amendmentRepository.deleteAll();
        manifestRepository.deleteAll();
        archiveRepository.deleteAll();
        eventRepository.deleteAll();
        chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .ifPresent(h -> { h.resetToEmpty(OffsetDateTime.now()); chainHeadRepository.save(h); });
        // Restore any constraints a prior test may have dropped, so DDL changes never leak
        // across tests sharing the container. Drop-if-exists then re-add makes this idempotent.
        jdbc.execute("ALTER TABLE audit_event DROP CONSTRAINT IF EXISTS ck_audit_event_content_hash_len");
        jdbc.execute("ALTER TABLE audit_event ADD CONSTRAINT ck_audit_event_content_hash_len "
                + "CHECK (octet_length(content_hash) = 32)");
        jdbc.execute("ALTER TABLE audit_event DROP CONSTRAINT IF EXISTS ck_audit_event_genesis_prev_hash");
        jdbc.execute("ALTER TABLE audit_event ADD CONSTRAINT ck_audit_event_genesis_prev_hash "
                + "CHECK ((sequence_number = 1 AND previous_hash IS NULL) "
                + "OR (sequence_number > 1 AND previous_hash IS NOT NULL))");
    }

    private void appendN(int n) {
        for (int i = 0; i < n; i++) {
            appendService.append(new AppendEventRequest(
                    "USER_LOGIN", "actor-" + i, "USER", "CLIENT_ACCOUNT", "acct-1",
                    "SUCCESS", null, null, null, null), UUID.randomUUID());
        }
    }

    @Test
    void intactChain_verifies() {
        appendN(5);
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isTrue();
        assertThat(r.verifiedRecords()).isEqualTo(5);
    }

    @Test
    void verificationRemainsConsistent_whileAppendsOccurConcurrently() throws Exception {
        appendN(3);
        var pool = java.util.concurrent.Executors.newFixedThreadPool(2);
        var stop = new java.util.concurrent.atomic.AtomicBoolean(false);
        var falseBreak = new java.util.concurrent.atomic.AtomicReference<ChainVerificationResult>();
        try {
            // Appender: keep appending until told to stop.
            var appender = pool.submit(() -> {
                while (!stop.get()) {
                    appendService.append(new AppendEventRequest(
                            "USER_LOGIN", "a", "USER", "CLIENT_ACCOUNT", "acct-1",
                            "SUCCESS", null, null, null, null), UUID.randomUUID());
                }
                return null;
            });
            // Verifier: verify many times while appends are happening. With REPEATABLE_READ,
            // each verification sees one consistent snapshot and must NEVER report a break —
            // a concurrent append committing mid-verify must not cause a false CHAIN_HEAD_MISMATCH.
            var verifier = pool.submit(() -> {
                for (int i = 0; i < 40; i++) {
                    ChainVerificationResult r = verificationService.verify();
                    if (!r.intact()) {
                        falseBreak.set(r);
                        return null;
                    }
                }
                return null;
            });
            verifier.get();
            stop.set(true);
            appender.get();
        } finally {
            pool.shutdownNow();
        }

        assertThat(falseBreak.get())
                .as("verification must not report a false break during concurrent appends")
                .isNull();
        // And a final verification of the settled chain is intact.
        assertThat(verificationService.verify().intact()).isTrue();
    }

    @Test
    void emptyChain_verifies() {
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isTrue();
        assertThat(r.verifiedRecords()).isZero();
    }

    // ---- modified field ----------------------------------------------------------------

    @Test
    void modifiedField_isDetectedAsContentHashMismatch() {
        appendN(3);
        // Tamper the actor_id of sequence 2 directly in the DB.
        jdbc.update("UPDATE audit_event SET actor_id = 'tampered' WHERE sequence_number = 2");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.firstInconsistentSequence()).isEqualTo(2L);
        assertThat(r.violationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
    }

    // ---- modified payload --------------------------------------------------------------

    @Test
    void modifiedPayload_isDetectedAsContentHashMismatch() {
        appendN(2);
        jdbc.update("UPDATE audit_event SET payload = '{\"x\":1}'::jsonb WHERE sequence_number = 1");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.firstInconsistentSequence()).isEqualTo(1L);
        assertThat(r.violationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
    }

    // ---- broken previous hash ----------------------------------------------------------

    @Test
    void brokenPreviousHash_isDetected() {
        appendN(3);
        // Overwrite sequence 3's previous_hash with a valid-length but wrong value.
        jdbc.update("UPDATE audit_event SET previous_hash = decode(repeat('00',32),'hex') "
                + "WHERE sequence_number = 3");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.firstInconsistentSequence()).isEqualTo(3L);
        assertThat(r.violationType()).isEqualTo(ChainViolationType.PREVIOUS_HASH_MISMATCH);
    }

    // ---- missing / deleted sequence ----------------------------------------------------

    @Test
    void missingSequence_isDetectedAsGap() {
        appendN(4);
        // Delete the middle record (sequence 2) directly.
        jdbc.update("DELETE FROM audit_event WHERE sequence_number = 2");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.firstInconsistentSequence()).isEqualTo(2L);
        assertThat(r.violationType()).isEqualTo(ChainViolationType.SEQUENCE_GAP);
    }

    // ---- malformed stored hash ---------------------------------------------------------

    @Test
    void malformedStoredHash_isDetected() {
        appendN(2);
        // The V1 CHECK constraint normally blocks a bad-length hash at the storage layer
        // (defense-in-depth). To exercise the verifier's OWN check — the last line of defense
        // if data arrives via a tampered restore / a DB without CHECKs — we temporarily drop
        // the constraint, corrupt the hash to 16 bytes, then verify.
        jdbc.execute("ALTER TABLE audit_event DROP CONSTRAINT ck_audit_event_content_hash_len");
        jdbc.update("UPDATE audit_event SET content_hash = decode(repeat('00',16),'hex') "
                + "WHERE sequence_number = 1");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.firstInconsistentSequence()).isEqualTo(1L);
        assertThat(r.violationType()).isEqualTo(ChainViolationType.MALFORMED_STORED_HASH);
    }

    // ---- inconsistent chain head -------------------------------------------------------

    @Test
    void inconsistentChainHead_isDetected() {
        appendN(3);
        // Tamper the head's current_sequence so it no longer matches the actual tip.
        jdbc.update("UPDATE audit_chain_head SET current_sequence = 99 WHERE id = 1");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.violationType()).isEqualTo(ChainViolationType.CHAIN_HEAD_MISMATCH);
    }

    @Test
    void genesisWithPreviousHash_isDetected() {
        appendN(1);
        // As above, the V1 CHECK blocks this at storage; drop it to exercise the verifier's
        // own genesis-link check (last line of defense against a tampered restore).
        jdbc.execute("ALTER TABLE audit_event DROP CONSTRAINT ck_audit_event_genesis_prev_hash");
        jdbc.update("UPDATE audit_event SET previous_hash = decode(repeat('00',32),'hex') "
                + "WHERE sequence_number = 1");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.firstInconsistentSequence()).isEqualTo(1L);
        assertThat(r.violationType()).isEqualTo(ChainViolationType.GENESIS_LINK_VIOLATION);
    }
}
