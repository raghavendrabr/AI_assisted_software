package com.raghavendra.audit.hardening;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Default posture: OpenAPI/Swagger is NOT public. With docs disabled (the base default, as under
 * the test profile), the doc paths are not accessible without authentication — they fall through
 * to the fail-closed {@code denyAll()} (401 without a key), and springdoc itself is switched off.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class SwaggerDisabledByDefaultTest {

    @Autowired
    private MockMvcTester mvc;

    @Test
    void apiDocs_notPublic_withoutKey() {
        // Not reachable anonymously (would be 200 if public). denyAll → 401.
        assertThat(mvc.get().uri("/v3/api-docs")).hasStatus(401);
    }

    @Test
    void swaggerUi_notPublic_withoutKey() {
        assertThat(mvc.get().uri("/swagger-ui/index.html")).hasStatus(401);
    }
}
