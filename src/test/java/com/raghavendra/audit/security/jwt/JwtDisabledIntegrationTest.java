package com.raghavendra.audit.security.jwt;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * With JWT disabled (the default), the service runs in API-key-only mode: a Bearer token is not a
 * recognized credential (no resource server is wired) so it is rejected as unauthenticated (401),
 * while API-key authentication continues to work.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class JwtDisabledIntegrationTest {

    @Autowired
    private MockMvcTester mvc;

    @Test
    void bearerToken_whenJwtDisabled_isUnauthorized_401() {
        // Any token value; JWT is off, so it is simply an unrecognized credential.
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, "Bearer any.token.value")).hasStatus(401);
    }

    @Test
    void apiKey_whenJwtDisabled_stillWorks() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key")).hasStatusOk();
    }
}
