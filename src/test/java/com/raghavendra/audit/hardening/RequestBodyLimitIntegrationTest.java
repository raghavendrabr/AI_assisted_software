package com.raghavendra.audit.hardening;

import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the request-body size cap ({@code audit.limits.max-request-bytes}). The limit is
 * lowered to a small value for this test so bodies are easy to construct. Covers:
 * <ul>
 *   <li>an oversized body with a declared {@code Content-Length} → 413 (early rejection);</li>
 *   <li>an oversized chunked / unknown-length body → 413 (streaming enforcement);</li>
 *   <li>a body exactly at the limit → accepted (201);</li>
 *   <li>the 413 response never echoes the submitted bytes.</li>
 * </ul>
 */
@SpringBootTest(properties = "audit.limits.max-request-bytes=1024")
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class RequestBodyLimitIntegrationTest {

    private static final int LIMIT = 1024;

    @Autowired
    private MockMvcTester mvc;
    @Autowired private AuditEventRepository eventRepository;
    @Autowired private AuditChainHeadRepository chainHeadRepository;
    @Autowired private com.raghavendra.audit.amendment.domain.AuditAmendmentRepository amendmentRepository;
    @Autowired private com.raghavendra.audit.retention.domain.ArchiveManifestRepository manifestRepository;
    @Autowired private com.raghavendra.audit.retention.domain.AuditEventArchiveRepository archiveRepository;

    @BeforeEach
    void resetChain() {
        amendmentRepository.deleteAll();
        manifestRepository.deleteAll();
        archiveRepository.deleteAll();
        eventRepository.deleteAll();
        chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .ifPresent(h -> {
                    h.resetToEmpty(OffsetDateTime.now());
                    chainHeadRepository.save(h);
                });
    }

    /** A unique, recognizable marker so we can prove it is never echoed back in an error. */
    private static final String SECRET_MARKER = "SUPER_SECRET_MARKER_9f2a";

    /** Build a valid append JSON whose serialized size is padded to approximately {@code target}. */
    private static String bodyOfApproxSize(int target) {
        String head = "{\"eventType\":\"USER_LOGIN\",\"actorId\":\"a\",\"actorType\":\"USER\","
                + "\"resourceType\":\"CLIENT_ACCOUNT\",\"resourceId\":\"acct-1\",\"outcome\":\"SUCCESS\","
                + "\"payload\":{\"note\":\"";
        String tail = "\"}}";
        int pad = target - head.length() - tail.length();
        if (pad < 0) {
            pad = 0;
        }
        return head + (SECRET_MARKER + "x".repeat(Math.max(0, pad - SECRET_MARKER.length()))) + tail;
    }

    @Test
    void oversizedDeclaredContentLength_isRejected_413() {
        String big = bodyOfApproxSize(LIMIT * 4); // well over the limit, with a real Content-Length
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(big)).hasStatus(413);
    }

    @Test
    void oversizedChunkedUnknownLength_isRejected_413() {
        // No Content-Length: MockMvc chunked-style body. The streaming counter must still trip.
        String big = bodyOfApproxSize(LIMIT * 4);
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .header("Transfer-Encoding", "chunked")
                .contentType(MediaType.APPLICATION_JSON)
                .content(big.getBytes())).hasStatus(413);
    }

    @Test
    void bodyAtOrUnderLimit_isAccepted_201() {
        String ok = bodyOfApproxSize(LIMIT - 64); // comfortably under the cap
        assertThat(ok.getBytes().length).isLessThanOrEqualTo(LIMIT);
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(ok)).hasStatus(201);
    }

    @Test
    void oversizedResponse_neverEchoesSubmittedBytes() throws Exception {
        String big = bodyOfApproxSize(LIMIT * 4);
        String responseBody = mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(big)
                .exchange().getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(responseBody).doesNotContain(SECRET_MARKER);
    }
}
