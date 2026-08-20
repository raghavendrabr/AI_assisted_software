package com.raghavendra.audit.observability;

import com.raghavendra.audit.common.observability.AuditMetrics;
import com.raghavendra.audit.event.application.AuditEventAppendService;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.search.Search;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end metrics: drive real operations and confirm the domain, HTTP, JVM, and Hikari series
 * appear in the Prometheus scrape. Also confirms append success is counted only after commit.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class MetricsIntegrationTest {

    @Autowired private MockMvcTester mvc;
    @Autowired private MeterRegistry registry;
    @Autowired private AuditEventAppendService appendService;
    @Autowired private AuditEventRepository eventRepository;
    @Autowired private AuditChainHeadRepository chainHeadRepository;
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
    }

    private static final String WRITE_BODY = """
            { "eventType":"USER_LOGIN","actorId":"a","actorType":"USER",
              "resourceType":"CLIENT_ACCOUNT","resourceId":"acct-1","outcome":"SUCCESS" }
            """;

    private double count(String name, String... tags) {
        var c = registry.find(name).tags(tags).counter();
        return c == null ? 0.0 : c.count();
    }

    @Test
    void appendSuccess_countedOnlyAfterCommit() {
        double before = count("audit.events.appended", "result", "success");
        mvc.post().uri("/api/v1/audit/events").header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(WRITE_BODY).exchange();
        // The MockMvc call committed the append transaction → success counter advanced by 1.
        assertThat(count("audit.events.appended", "result", "success")).isEqualTo(before + 1);
    }

    @Test
    void rolledBackAppend_incrementsFailure_notSuccess() {
        double successBefore = count("audit.events.appended", "result", "success");
        double failBefore = count("audit.append.failures");
        // Force a failure inside the transaction by supplying a duplicate eventId via the service.
        java.util.UUID id = java.util.UUID.randomUUID();
        var req = new com.raghavendra.audit.event.api.AppendEventRequest(
                "E", "a", "U", "CLIENT_ACCOUNT", "r", "SUCCESS", null, null, null, null);
        appendService.append(req, id); // first succeeds (commits in this test thread)
        try {
            appendService.append(req, id); // same id → DuplicateEventIdException → rollback
        } catch (RuntimeException expected) {
            // expected
        }
        assertThat(count("audit.append.failures")).isGreaterThan(failBefore);
        // Exactly one success was added (the first append), not two.
        assertThat(count("audit.events.appended", "result", "success")).isEqualTo(successBefore + 1);
    }

    @Test
    void verify_recordsIntact() {
        double before = count("audit.chain.verifications", "result", "intact");
        mvc.get().uri("/api/v1/audit/verify").header("X-API-Key", "test-compliance-key").exchange();
        assertThat(count("audit.chain.verifications", "result", "intact")).isEqualTo(before + 1);
    }

    @Test
    void export_recordsSuccess() {
        double before = count("audit.export.operations", "result", "success");
        mvc.post().uri("/api/v1/audit/events").header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(WRITE_BODY).exchange();
        mvc.get().uri("/api/v1/audit/export?resourceId=acct-1")
                .header("X-API-Key", "test-compliance-key").exchange();
        assertThat(count("audit.export.operations", "result", "success")).isEqualTo(before + 1);
    }

    @Test
    void authentication_recordedOncePerOutcome() {
        double keySuccessBefore = count("audit.authentication.attempts",
                "result", "success", "method", "api_key", "reason", "valid-key");
        mvc.get().uri("/api/v1/audit/verify").header("X-API-Key", "test-compliance-key").exchange();
        assertThat(count("audit.authentication.attempts",
                "result", "success", "method", "api_key", "reason", "valid-key"))
                .isEqualTo(keySuccessBefore + 1);
    }

    @Test
    void prometheusScrape_containsDomainHttpJvmAndHikariSeries() throws Exception {
        // Generate some traffic first.
        mvc.post().uri("/api/v1/audit/events").header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(WRITE_BODY).exchange();
        mvc.get().uri("/api/v1/audit/verify").header("X-API-Key", "test-compliance-key").exchange();

        String scrape = mvc.get().uri("/actuator/prometheus")
                .header("X-API-Key", "test-admin-key")
                .exchange().getResponse().getContentAsString(StandardCharsets.UTF_8);

        // Domain (dotted names are translated to _ by Prometheus).
        assertThat(scrape).contains("audit_events_appended_total");
        assertThat(scrape).contains("audit_chain_verifications_total");
        assertThat(scrape).contains("audit_authentication_attempts_total");
        // HTTP server + JVM + Hikari — confirmed present at runtime (not asserting Flyway).
        assertThat(scrape).contains("http_server_requests");
        assertThat(scrape).contains("jvm_memory_used_bytes");
        assertThat(scrape).contains("hikaricp_connections");
    }

    @Test
    void prometheusScrape_hasNoHighCardinalityOrSensitiveLabels() throws Exception {
        mvc.get().uri("/api/v1/audit/verify").header("X-API-Key", "test-compliance-key").exchange();
        String scrape = mvc.get().uri("/actuator/prometheus")
                .header("X-API-Key", "test-admin-key")
                .exchange().getResponse().getContentAsString(StandardCharsets.UTF_8);
        // Only the domain metric lines; assert no forbidden label keys appear on audit_* series.
        scrape.lines().filter(l -> l.startsWith("audit_")).forEach(line ->
                assertThat(line)
                        .doesNotContain("actorId").doesNotContain("resourceId")
                        .doesNotContain("eventId").doesNotContain("keyId")
                        .doesNotContain("requestId").doesNotContain("subject"));
    }
}
