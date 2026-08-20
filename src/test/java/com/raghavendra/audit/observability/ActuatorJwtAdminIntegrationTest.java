package com.raghavendra.audit.observability;

import com.raghavendra.audit.security.jwt.AbstractJwtEnabledTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * When JWT is enabled, an ADMIN-scoped JWT can reach the ADMIN-only actuator endpoints, while a
 * non-admin scope cannot.
 */
class ActuatorJwtAdminIntegrationTest extends AbstractJwtEnabledTest {

    @Autowired
    private MockMvcTester mvc;

    @Test
    void prometheus_withAdminJwt_200() {
        assertThat(mvc.get().uri("/actuator/prometheus")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken("audit.admin"))))
                .hasStatusOk();
    }

    @Test
    void prometheus_withReadJwt_403() {
        assertThat(mvc.get().uri("/actuator/prometheus")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken("audit.read"))))
                .hasStatus(403);
    }

    @Test
    void liveness_stillPublic_withJwtEnabled() {
        assertThat(mvc.get().uri("/actuator/health/liveness")).hasStatusOk();
    }
}
