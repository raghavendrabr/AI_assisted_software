package com.raghavendra.audit.observability;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Actuator exposure + authorization matrix:
 * <ul>
 *   <li>liveness/readiness probes are public (200), readiness reflects the DB (available here);</li>
 *   <li>public probes expose status only, not sensitive component details;</li>
 *   <li>full health/info/prometheus require ADMIN (401 without a credential; 403 for non-admins;
 *       200 for an ADMIN API key);</li>
 *   <li>dangerous / non-exposed endpoints are 404;</li>
 *   <li>the existing API denyAll behavior is intact.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class ActuatorSecurityIntegrationTest {

    @Autowired
    private MockMvcTester mvc;

    // ---- public probes -----------------------------------------------------------------

    @Test
    void liveness_isPublic_200() {
        assertThat(mvc.get().uri("/actuator/health/liveness")).hasStatusOk();
    }

    @Test
    void readiness_isPublic_200_withDbAvailable() {
        assertThat(mvc.get().uri("/actuator/health/readiness")).hasStatusOk();
    }

    @Test
    void publicProbe_revealsStatusOnly_notComponentDetails() {
        MockHttpServletResponse r = mvc.get().uri("/actuator/health/liveness")
                .exchange().getResponse();
        String body = safeBody(r);
        assertThat(body).contains("\"status\"");
        // No component/detail breakdown for an unauthenticated caller.
        assertThat(body).doesNotContain("\"components\"");
        assertThat(body).doesNotContain("\"details\"");
    }

    // ---- full endpoints require ADMIN --------------------------------------------------

    @Test
    void fullHealth_withoutCredential_401() {
        assertThat(mvc.get().uri("/actuator/health")).hasStatus(401);
    }

    @Test
    void prometheus_withoutCredential_401() {
        assertThat(mvc.get().uri("/actuator/prometheus")).hasStatus(401);
    }

    @Test
    void info_withoutCredential_401() {
        assertThat(mvc.get().uri("/actuator/info")).hasStatus(401);
    }

    @Test
    void prometheus_withNonAdminKeys_403() {
        assertThat(mvc.get().uri("/actuator/prometheus")
                .header("X-API-Key", "test-writer-key")).hasStatus(403);
        assertThat(mvc.get().uri("/actuator/prometheus")
                .header("X-API-Key", "test-compliance-key")).hasStatus(403);
    }

    @Test
    void fullHealth_withNonAdminKey_403() {
        assertThat(mvc.get().uri("/actuator/health")
                .header("X-API-Key", "test-compliance-key")).hasStatus(403);
    }

    @Test
    void prometheus_withAdminKey_200() {
        assertThat(mvc.get().uri("/actuator/prometheus")
                .header("X-API-Key", "test-admin-key")).hasStatusOk();
    }

    @Test
    void health_withAdminKey_200_withDetails() {
        MockHttpServletResponse r = mvc.get().uri("/actuator/health")
                .header("X-API-Key", "test-admin-key").exchange().getResponse();
        assertThat(r.getStatus()).isEqualTo(200);
        // ADMIN sees component details (show-details=when-authorized).
        assertThat(safeBody(r)).contains("\"components\"");
    }

    @Test
    void info_withAdminKey_200() {
        assertThat(mvc.get().uri("/actuator/info")
                .header("X-API-Key", "test-admin-key")).hasStatusOk();
    }

    // ---- dangerous / non-exposed endpoints are not available ---------------------------

    @Test
    void dangerousEndpoints_areNotAccessible() {
        // These endpoints are NOT exposed. They are therefore not reachable even by an ADMIN:
        // the fail-closed security chain denies the path (403) before it could ever be served, and
        // an exposed one would 404 — either way, never a 200. Asserting "not 200" captures the real
        // security property without depending on 403-vs-404 ordering.
        for (String ep : new String[]{"env", "configprops", "beans", "mappings", "loggers",
                "heapdump", "threaddump", "shutdown", "metrics"}) {
            int status = mvc.get().uri("/actuator/" + ep)
                    .header("X-API-Key", "test-admin-key")
                    .exchange().getResponse().getStatus();
            assertThat(status)
                    .as("actuator/%s must not be served (got %d)", ep, status)
                    .isIn(403, 404);
        }
    }

    // ---- existing API authorization still intact ---------------------------------------

    @Test
    void apiDenyAll_stillIntact() {
        assertThat(mvc.get().uri("/api/v1/audit/some-unlisted")
                .header("X-API-Key", "test-admin-key")).hasStatus(403);
        assertThat(mvc.get().uri("/api/v1/audit/some-unlisted")).hasStatus(401);
    }

    private static String safeBody(MockHttpServletResponse r) {
        try {
            return r.getContentAsString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
}
