package com.raghavendra.audit.hardening;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Local/dev posture: when {@code audit.docs.enabled=true} and {@code audit.docs.public=true} (the
 * behavior the {@code local} profile enables), the OpenAPI JSON is reachable without a key.
 */
@SpringBootTest(properties = {
        "audit.docs.enabled=true",
        "audit.docs.public=true"
})
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class SwaggerLocalPublicTest {

    @Autowired
    private MockMvcTester mvc;

    @Test
    void apiDocs_public_returns200_withoutKey() {
        assertThat(mvc.get().uri("/v3/api-docs")).hasStatusOk();
    }
}
