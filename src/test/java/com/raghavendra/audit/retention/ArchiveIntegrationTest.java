package com.raghavendra.audit.retention;

import com.raghavendra.audit.amendment.domain.AuditAmendmentRepository;
import com.raghavendra.audit.event.api.AppendEventRequest;
import com.raghavendra.audit.event.application.AuditEventAppendService;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.redaction.RedactionService;
import com.raghavendra.audit.retention.domain.ArchiveManifestEntity;
import com.raghavendra.audit.retention.domain.ArchiveManifestRepository;
import com.raghavendra.audit.retention.domain.AuditEventArchiveRepository;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import com.raghavendra.audit.verify.ChainVerificationResult;
import com.raghavendra.audit.verify.ChainVerificationService;
import com.raghavendra.audit.verify.ChainViolationType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Retention/archival correctness: archive the oldest prefix atomically, keep verification intact
 * across active+archive, detect archive tampering, redact archived events, and roll back on
 * failure / under concurrency.
 */
@SpringBootTest
@AbstractPostgresIntegrationTest.WithPostgres
class ArchiveIntegrationTest {

    @Autowired private AuditEventAppendService appendService;
    @Autowired private ArchiveService archiveService;
    @Autowired private RedactionService redactionService;
    @Autowired private ChainVerificationService verificationService;
    @Autowired private AuditEventRepository eventRepository;
    @Autowired private AuditEventArchiveRepository archiveRepository;
    @Autowired private ArchiveManifestRepository manifestRepository;
    @Autowired private AuditAmendmentRepository amendmentRepository;
    @Autowired private AuditChainHeadRepository chainHeadRepository;
    @Autowired private JdbcTemplate jdbc;

    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void reset() {
        amendmentRepository.deleteAll();
        manifestRepository.deleteAll();
        archiveRepository.deleteAll();
        eventRepository.deleteAll();
        chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .ifPresent(h -> { h.resetToEmpty(OffsetDateTime.now()); chainHeadRepository.save(h); });
    }

    private OffsetDateTime T(int minute) {
        return OffsetDateTime.of(2026, 8, 1, 10, minute, 0, 0, ZoneOffset.UTC);
    }

    private void appendAt(OffsetDateTime ts) {
        appendService.append(new AppendEventRequest(
                "USER_LOGIN", "actor", "USER", "CLIENT_ACCOUNT", "acct-1",
                "SUCCESS", null, null, null, ts), UUID.randomUUID());
    }

    private long appendRedactableAt(OffsetDateTime ts, String value) {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("accountNumber", value);
        return appendService.append(new AppendEventRequest(
                "CLIENT_ACCOUNT_VIEWED", "emp-1", "EMPLOYEE", "CLIENT_ACCOUNT", "acct-1",
                "SUCCESS", null, payload, List.of("accountNumber"), ts), UUID.randomUUID())
                .getSequenceNumber();
    }

    // ---- happy path --------------------------------------------------------------------

    @Test
    void archivesOldestPrefix_movesRecords_andChainStaysIntact() {
        appendAt(T(0)); appendAt(T(1)); appendAt(T(2)); appendAt(T(5)); appendAt(T(6));

        // Archive everything strictly before T(3): sequences 1..3.
        ArchiveManifestEntity m = archiveService.archiveOlderThan(T(3), "admin-1");

        assertThat(m.getFromSequence()).isEqualTo(1);
        assertThat(m.getToSequence()).isEqualTo(3);
        assertThat(m.getRecordCount()).isEqualTo(3);
        assertThat(eventRepository.count()).isEqualTo(2);   // 4,5 remain active
        assertThat(archiveRepository.count()).isEqualTo(3); // 1,2,3 archived
        // One ARCHIVE amendment.
        assertThat(amendmentRepository.findAll()).hasSize(1);
        // Verification reads active + archive as one chain → intact.
        assertThat(verificationService.verify().intact()).isTrue();
    }

    @Test
    void archivesOnlyContiguousOldestPrefix() {
        appendAt(T(0)); appendAt(T(5)); appendAt(T(1));
        // Only sequence 1 (T0) is before T(3) AND contiguous from the start; sequence 2 is T(5),
        // so the prefix stops there even though sequence 3 is old.
        ArchiveManifestEntity m = archiveService.archiveOlderThan(T(3), "admin-1");
        assertThat(m.getFromSequence()).isEqualTo(1);
        assertThat(m.getToSequence()).isEqualTo(1);
        assertThat(archiveRepository.count()).isEqualTo(1);
    }

    @Test
    void nothingEligible_throws() {
        appendAt(T(5));
        assertThatThrownBy(() -> archiveService.archiveOlderThan(T(3), "admin-1"))
                .isInstanceOf(ArchiveException.class);
    }

    // ---- tamper detection --------------------------------------------------------------

    @Test
    void modifiedArchivedRecord_isDetected() {
        appendAt(T(0)); appendAt(T(1)); appendAt(T(5));
        archiveService.archiveOlderThan(T(3), "admin-1"); // archives 1,2
        // Tamper an archived record's actor.
        jdbc.update("UPDATE audit_event_archive SET actor_id = 'x' WHERE sequence_number = 1");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.violationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
    }

    @Test
    void deletedArchivedRecord_isDetectedAsGap() {
        appendAt(T(0)); appendAt(T(1)); appendAt(T(2)); appendAt(T(5));
        archiveService.archiveOlderThan(T(3), "admin-1"); // archives 1,2,3
        jdbc.update("DELETE FROM audit_event_archive WHERE sequence_number = 2");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        // Missing record shows as a gap in the merged stream OR an archive-proof mismatch
        // (manifest count no longer matches). Either is a correct detection.
        assertThat(r.violationType()).isIn(
                ChainViolationType.SEQUENCE_GAP, ChainViolationType.ARCHIVE_PROOF_MISMATCH);
    }

    @Test
    void tamperedManifest_isDetected() {
        appendAt(T(0)); appendAt(T(1)); appendAt(T(5));
        archiveService.archiveOlderThan(T(3), "admin-1");
        // Change the manifest's record_count so it no longer matches its hash / the records.
        jdbc.update("UPDATE archive_manifest SET record_count = 99");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.violationType()).isEqualTo(ChainViolationType.ARCHIVE_PROOF_MISMATCH);
    }

    @Test
    void duplicatedSequenceAcrossActiveAndArchive_isDetected() {
        appendAt(T(0)); appendAt(T(1)); appendAt(T(5));
        archiveService.archiveOlderThan(T(3), "admin-1"); // archives 1,2 (active: 3)
        // Simulate a duplicate: copy archived sequence 1 back into the ACTIVE table (it now
        // exists in both). The merged stream sees sequence 1 twice → not a clean 1,2,3,...
        jdbc.update("INSERT INTO audit_event (event_id, sequence_number, actor_id, actor_type, "
                + "action, resource_type, resource_id, outcome, event_timestamp, recorded_at, "
                + "schema_version, payload, previous_hash, content_hash) "
                + "SELECT event_id, sequence_number, actor_id, actor_type, action, resource_type, "
                + "resource_id, outcome, event_timestamp, recorded_at, schema_version, payload, "
                + "previous_hash, content_hash FROM audit_event_archive WHERE sequence_number = 1");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        // Duplicate sequence breaks the strict 1,2,3 expectation (or the archive-proof count).
        assertThat(r.violationType()).isIn(
                ChainViolationType.SEQUENCE_GAP, ChainViolationType.ARCHIVE_PROOF_MISMATCH,
                ChainViolationType.PREVIOUS_HASH_MISMATCH);
    }

    @Test
    void failedArchive_rollsBack_leavingEverythingUnchanged() {
        appendAt(T(0)); appendAt(T(1)); appendAt(T(5));
        long activeBefore = eventRepository.count();
        long archiveBefore = archiveRepository.count();
        long manifestBefore = manifestRepository.count();
        long amendmentsBefore = amendmentRepository.count();
        var headBefore = chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID).orElseThrow();
        long eventTipBefore = headBefore.getCurrentSequence();
        long amendTipBefore = headBefore.getLastAmendmentSeq();

        // A no-eligible-records archive fails and must write nothing.
        assertThatThrownBy(() -> archiveService.archiveOlderThan(T(0), "admin-1"))
                .isInstanceOf(ArchiveException.class); // T(0) excludes everything (strictly before)

        assertThat(eventRepository.count()).isEqualTo(activeBefore);
        assertThat(archiveRepository.count()).isEqualTo(archiveBefore);
        assertThat(manifestRepository.count()).isEqualTo(manifestBefore);
        assertThat(amendmentRepository.count()).isEqualTo(amendmentsBefore);
        var headAfter = chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID).orElseThrow();
        assertThat(headAfter.getCurrentSequence()).isEqualTo(eventTipBefore);
        assertThat(headAfter.getLastAmendmentSeq()).isEqualTo(amendTipBefore);
        assertThat(verificationService.verify().intact()).isTrue();
    }

    // ---- redaction on archived events --------------------------------------------------

    @Test
    void redactionWorksForArchivedEvent_andChainStaysIntact() {
        long seq = appendRedactableAt(T(0), "SECRET-123");
        appendAt(T(5));
        archiveService.archiveOlderThan(T(3), "admin-1"); // archives the redactable event

        assertThat(archiveRepository.existsBySequenceNumber(seq)).isTrue();
        redactionService.redactField(seq, "accountNumber", "admin-1");

        var archived = archiveRepository.findBySequenceNumber(seq).orElseThrow();
        assertThat(archived.getPayload()).contains("\"value\": null");
        assertThat(verificationService.verify().intact()).isTrue();
    }

    // ---- rollback + concurrency --------------------------------------------------------

    @Test
    void concurrentArchive_onlyOneMovesEachRecord_chainIntact() throws Exception {
        for (int i = 0; i < 5; i++) {
            appendAt(T(i));
        }
        var pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Object>> tasks = List.of(
                    () -> tryArchive(T(3)), () -> tryArchive(T(3)),
                    () -> tryArchive(T(3)), () -> tryArchive(T(3)));
            var futures = pool.invokeAll(tasks);
            for (var f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }
        // Records 1,2,3 archived exactly once (no duplicates), 4,5 remain; chain intact.
        assertThat(archiveRepository.count()).isEqualTo(3);
        assertThat(eventRepository.count()).isEqualTo(2);
        assertThat(verificationService.verify().intact()).isTrue();
    }

    private Object tryArchive(OffsetDateTime cutoff) {
        try {
            return archiveService.archiveOlderThan(cutoff, "admin-c");
        } catch (RuntimeException ex) {
            return ex; // later attempts find nothing eligible → ArchiveException
        }
    }
}
