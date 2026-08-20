package com.raghavendra.audit.observability;

import com.raghavendra.audit.common.observability.CorrelationIdFilter;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Correlation-id behavior: a valid inbound id is echoed; a missing/invalid/oversized id is replaced
 * by a generated UUID; the id is present on success AND error responses (401/403/413); and MDC does
 * not leak after the request.
 */
@SpringBootTest(properties = "audit.limits.max-request-bytes=1024")
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class CorrelationIdIntegrationTest {

    private static final String HEADER = CorrelationIdFilter.REQUEST_ID_HEADER;
    private static final java.util.regex.Pattern SAFE =
            java.util.regex.Pattern.compile("[A-Za-z0-9._-]{1,64}");

    @Autowired
    private MockMvcTester mvc;

    private String requestIdOf(MockHttpServletResponse r) {
        return r.getHeader(HEADER);
    }

    @Test
    void validInboundId_isEchoed() {
        MockHttpServletResponse r = mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key")
                .header(HEADER, "req-ABC_123.xyz").exchange().getResponse();
        assertThat(requestIdOf(r)).isEqualTo("req-ABC_123.xyz");
    }

    @Test
    void missingId_generatesUuid() {
        MockHttpServletResponse r = mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key").exchange().getResponse();
        String id = requestIdOf(r);
        assertThat(id).isNotBlank();
        assertThat(SAFE.matcher(id).matches()).isTrue(); // a UUID matches the safe pattern
    }

    @Test
    void oversizedOrInvalidId_isReplaced() {
        String tooLong = "x".repeat(100);
        MockHttpServletResponse r1 = mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key")
                .header(HEADER, tooLong).exchange().getResponse();
        assertThat(requestIdOf(r1)).isNotEqualTo(tooLong);
        assertThat(requestIdOf(r1)).hasSizeLessThanOrEqualTo(64);

        // A value with disallowed characters (spaces, slashes) is invalid → replaced with a UUID
        // (and never echoed verbatim). Uses a single-line value so the servlet header parser accepts
        // it as input; the filter is what rejects/replaces it.
        MockHttpServletResponse r2 = mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key")
                .header(HEADER, "bad id with spaces/and slashes").exchange().getResponse();
        assertThat(requestIdOf(r2)).doesNotContain(" ").doesNotContain("/");
        assertThat(SAFE.matcher(requestIdOf(r2)).matches()).isTrue();
    }

    // ---- present on error responses ----------------------------------------------------

    @Test
    void requestId_presentOn401() {
        MockHttpServletResponse r = mvc.get().uri("/api/v1/audit/verify").exchange().getResponse();
        assertThat(r.getStatus()).isEqualTo(401);
        assertThat(requestIdOf(r)).isNotBlank();
    }

    @Test
    void requestId_presentOn403() {
        MockHttpServletResponse r = mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-writer-key").exchange().getResponse();
        assertThat(r.getStatus()).isEqualTo(403);
        assertThat(requestIdOf(r)).isNotBlank();
    }

    @Test
    void requestId_presentOn413() {
        String big = "{\"eventType\":\"X\",\"actorId\":\"a\",\"actorType\":\"U\","
                + "\"resourceType\":\"CLIENT_ACCOUNT\",\"resourceId\":\"r\",\"outcome\":\"S\","
                + "\"payload\":{\"note\":\"" + "x".repeat(4000) + "\"}}";
        MockHttpServletResponse r = mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(big).exchange().getResponse();
        assertThat(r.getStatus()).isEqualTo(413);
        assertThat(requestIdOf(r)).isNotBlank();
    }

    // ---- no MDC leakage ----------------------------------------------------------------

    @Test
    void mdc_isClear_afterRequest() {
        mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key").exchange();
        // After the request completes, the calling thread's MDC must not retain a requestId.
        assertThat(MDC.get(CorrelationIdFilter.MDC_KEY)).isNull();
    }
}
