package com.raghavendra.audit.redaction;

import com.raghavendra.audit.amendment.domain.AuditAmendmentRepository;
import com.raghavendra.audit.event.api.AppendEventRequest;
import com.raghavendra.audit.event.application.AuditEventAppendService;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.event.domain.AuditEventRepository;
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
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Redaction correctness: an authorized redaction nulls the plaintext, is backed by an amendment,
 * and leaves BOTH chains intact; an unauthorized null (no amendment) is detected; tampering the
 * plaintext or salt is detected via the commitment.
 */
@SpringBootTest
@AbstractPostgresIntegrationTest.WithPostgres
class RedactionIntegrationTest {

    @Autowired private AuditEventAppendService appendService;
    @Autowired private RedactionService redactionService;
    @Autowired private ChainVerificationService verificationService;
    @Autowired private AuditEventRepository eventRepository;
    @Autowired private AuditAmendmentRepository amendmentRepository;
    @Autowired private AuditChainHeadRepository chainHeadRepository;
    @Autowired private JdbcTemplate jdbc;

    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void reset() {
        amendmentRepository.deleteAll();
        eventRepository.deleteAll();
        chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .ifPresent(h -> { h.resetToEmpty(OffsetDateTime.now()); chainHeadRepository.save(h); });
    }

    private long appendWithRedactable(String accountNumber) {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("accountNumber", accountNumber);
        payload.put("channel", "WEB");
        return appendService.append(new AppendEventRequest(
                "CLIENT_ACCOUNT_VIEWED", "emp-1", "EMPLOYEE", "CLIENT_ACCOUNT", "acct-1",
                "SUCCESS", "support", payload, List.of("accountNumber"), null),
                UUID.randomUUID()).getSequenceNumber();
    }

    @Test
    void write_storesRedactableEnvelope_andChainVerifies() {
        appendWithRedactable("1234567890");
        AuditEventEntity e = eventRepository.findAll().get(0);
        // Note: PostgreSQL JSONB normalizes spacing ("key": value), so match loosely.
        assertThat(e.getPayload()).contains("\"salt\"").contains("\"commitment\"")
                .contains("1234567890");
        assertThat(verificationService.verify().intact()).isTrue();
    }

    @Test
    void authorizedRedaction_nullsPlaintext_backsWithAmendment_andChainStaysIntact() {
        long seq = appendWithRedactable("1234567890");
        byte[] hashBefore = eventRepository.findAll().get(0).getContentHash();

        redactionService.redactField(seq, "accountNumber", "admin-1");

        AuditEventEntity after = eventRepository.findAll().get(0);
        // Plaintext value is now null; salt + commitment remain. (JSONB normalizes spacing.)
        assertThat(after.getPayload()).contains("\"value\": null")
                .contains("\"salt\"").contains("\"commitment\"");
        // content_hash is UNCHANGED (hash never covered the value).
        assertThat(after.getContentHash()).isEqualTo(hashBefore);
        // An amendment now backs the redaction.
        assertThat(amendmentRepository.findAll()).hasSize(1);
        // Both chains verify.
        assertThat(verificationService.verify().intact()).isTrue();
    }

    @Test
    void unauthorizedNull_withNoAmendment_isDetected() {
        long seq = appendWithRedactable("1234567890");
        // Attacker nulls the plaintext value directly, WITHOUT an amendment.
        var e = eventRepository.findAll().get(0);
        ObjectNode payload = (ObjectNode) mapper.readTree(e.getPayload());
        ((ObjectNode) payload.get("accountNumber")).set("value", mapper.nullNode());
        jdbc.update("UPDATE audit_event SET payload = CAST(? AS jsonb) WHERE sequence_number = ?",
                payload.toString(), seq);

        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.violationType()).isEqualTo(ChainViolationType.REDACTION_UNBACKED);
    }

    @Test
    void tamperedPlaintextValue_isDetectedByCommitment() {
        long seq = appendWithRedactable("1234567890");
        var e = eventRepository.findAll().get(0);
        ObjectNode payload = (ObjectNode) mapper.readTree(e.getPayload());
        ((ObjectNode) payload.get("accountNumber")).put("value", "9999999999"); // changed value
        jdbc.update("UPDATE audit_event SET payload = CAST(? AS jsonb) WHERE sequence_number = ?",
                payload.toString(), seq);

        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.violationType()).isEqualTo(ChainViolationType.COMMITMENT_MISMATCH);
    }

    @Test
    void redactingUnknownEvent_throwsNotFound() {
        assertThatThrownBy(() -> redactionService.redactField(999L, "accountNumber", "admin-1"))
                .isInstanceOf(RedactionException.class)
                .matches(ex -> ((RedactionException) ex).isNotFound());
    }

    @Test
    void redactingNonRedactableField_throws() {
        long seq = appendWithRedactable("1234567890");
        assertThatThrownBy(() -> redactionService.redactField(seq, "channel", "admin-1"))
                .isInstanceOf(RedactionException.class);
    }

    @Test
    void redactingAlreadyRedactedField_throws() {
        long seq = appendWithRedactable("1234567890");
        redactionService.redactField(seq, "accountNumber", "admin-1");
        assertThatThrownBy(() -> redactionService.redactField(seq, "accountNumber", "admin-1"))
                .isInstanceOf(RedactionException.class);
    }

    @Test
    void amendmentRecord_containsNoPlaintextValue() {
        long seq = appendWithRedactable("SENSITIVE-9999");
        redactionService.redactField(seq, "accountNumber", "admin-1");
        var amendment = amendmentRepository.findAll().get(0);
        // The amendment records the field name and actor — never the redacted plaintext.
        assertThat(amendment.getDetail()).contains("accountNumber").doesNotContain("SENSITIVE-9999");
        assertThat(amendment.getActorId()).isEqualTo("admin-1");
    }

    @Test
    void concurrentSameFieldRedaction_exactlyOneSucceeds() throws Exception {
        long seq = appendWithRedactable("1234567890");
        int threads = 6;
        var pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
        var successes = new java.util.concurrent.atomic.AtomicInteger(0);
        var failures = new java.util.concurrent.atomic.AtomicInteger(0);
        try {
            var start = new java.util.concurrent.CountDownLatch(1);
            var tasks = new java.util.ArrayList<java.util.concurrent.Callable<Void>>();
            for (int i = 0; i < threads; i++) {
                tasks.add(() -> {
                    start.await();
                    try {
                        redactionService.redactField(seq, "accountNumber", "admin-" + Thread.currentThread().getId());
                        successes.incrementAndGet();
                    } catch (RuntimeException ex) {
                        failures.incrementAndGet(); // already-redacted or lock-loser
                    }
                    return null;
                });
            }
            var futures = tasks.stream().map(pool::submit).toList();
            start.countDown();
            for (var f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        // Exactly one redaction commits; the rest are rejected. One amendment, chain intact.
        assertThat(successes.get()).isEqualTo(1);
        assertThat(failures.get()).isEqualTo(threads - 1);
        assertThat(amendmentRepository.findAll()).hasSize(1);
        assertThat(verificationService.verify().intact()).isTrue();
    }

    @Test
    void failedRedaction_rollsBack_leavingBothChainsUnchanged() {
        long seq = appendWithRedactable("1234567890");
        byte[] eventHashBefore = eventRepository.findAll().get(0).getContentHash();
        long amendmentsBefore = amendmentRepository.count();
        var headBefore = chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID).orElseThrow();
        long amendSeqBefore = headBefore.getLastAmendmentSeq();

        // A redaction that fails validation (non-redactable field) must write nothing.
        assertThatThrownBy(() -> redactionService.redactField(seq, "channel", "admin-1"))
                .isInstanceOf(RedactionException.class);

        // Base event unchanged; no amendment added; amendment head not advanced.
        assertThat(eventRepository.findAll().get(0).getContentHash()).isEqualTo(eventHashBefore);
        assertThat(amendmentRepository.count()).isEqualTo(amendmentsBefore);
        assertThat(chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID).orElseThrow()
                .getLastAmendmentSeq()).isEqualTo(amendSeqBefore);
        // Both chains still verify.
        assertThat(verificationService.verify().intact()).isTrue();
    }

    @Test
    void tamperedAmendment_isDetected() {
        long seq = appendWithRedactable("1234567890");
        redactionService.redactField(seq, "accountNumber", "admin-1");
        // Tamper the amendment's actor_id directly → amendment content hash no longer matches.
        jdbc.update("UPDATE audit_amendment SET actor_id = 'tampered' WHERE amendment_seq = 1");
        ChainVerificationResult r = verificationService.verify();
        assertThat(r.intact()).isFalse();
        assertThat(r.violationType()).isEqualTo(ChainViolationType.AMENDMENT_CHAIN_BROKEN);
    }
}
