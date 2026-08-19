package com.raghavendra.audit.hardening;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the response security-header policy: Spring Security's defaults (nosniff, frame DENY)
 * are retained, Referrer-Policy and Permissions-Policy are added, and HSTS is absent over plain
 * HTTP (it only applies to HTTPS). Also confirms that forwarded headers are NOT trusted under the
 * default profile.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class SecurityHeadersIntegrationTest {

    @Autowired
    private MockMvcTester mvc;

    private MockHttpServletResponse verifyResponse() {
        return mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key")
                .exchange().getResponse();
    }

    @Test
    void defaultHeaders_present() {
        MockHttpServletResponse resp = verifyResponse();
        assertThat(resp.getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(resp.getHeader("X-Frame-Options")).isEqualTo("DENY");
    }

    @Test
    void referrerAndPermissionsPolicy_added() {
        MockHttpServletResponse resp = verifyResponse();
        assertThat(resp.getHeader("Referrer-Policy")).isEqualTo("no-referrer");
        assertThat(resp.getHeader("Permissions-Policy")).isNotBlank();
        assertThat(resp.getHeader("Permissions-Policy")).contains("geolocation=()");
    }

    @Test
    void hsts_absentOverHttp() {
        MockHttpServletResponse resp = verifyResponse();
        // MockMvc requests are plain HTTP; HSTS must not be emitted for non-secure requests.
        assertThat(resp.getHeader("Strict-Transport-Security")).isNull();
    }

    @Test
    void forwardedHeaders_notTrusted_inDefaultProfile() {
        // With forward-headers-strategy=none (default), a spoofed X-Forwarded-Proto must not cause
        // the app to believe the request was secure. We assert HSTS is still absent even though the
        // client claims https — proving the forwarded header was ignored.
        MockHttpServletResponse resp = mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key")
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-For", "203.0.113.9")
                .exchange().getResponse();
        assertThat(resp.getHeader("Strict-Transport-Security")).isNull();
    }
}
