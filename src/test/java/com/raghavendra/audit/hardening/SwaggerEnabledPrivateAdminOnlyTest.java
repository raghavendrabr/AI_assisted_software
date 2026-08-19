package com.raghavendra.audit.hardening;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Enabled-but-not-public posture: when {@code audit.docs.enabled=true} and
 * {@code audit.docs.public=false}, the OpenAPI docs require ADMIN — no key → 401, non-admin key →
 * 403, ADMIN key → 200.
 */
@SpringBootTest(properties = {
        "audit.docs.enabled=true",
        "audit.docs.public=false"
})
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class SwaggerEnabledPrivateAdminOnlyTest {

    @Autowired
    private MockMvcTester mvc;

    @Test
    void apiDocs_withoutKey_isUnauthorized_401() {
        assertThat(mvc.get().uri("/v3/api-docs")).hasStatus(401);
    }

    @Test
    void apiDocs_withNonAdminKey_isForbidden_403() {
        assertThat(mvc.get().uri("/v3/api-docs")
                .header("X-API-Key", "test-compliance-key")).hasStatus(403);
    }

    @Test
    void apiDocs_withAdminKey_isAllowed_200() {
        assertThat(mvc.get().uri("/v3/api-docs")
                .header("X-API-Key", "test-admin-key")).hasStatusOk();
    }
}
