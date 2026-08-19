package com.raghavendra.audit.security.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Response-protocol checks for the dual-mode auth surface:
 * <ul>
 *   <li>invalid / expired / malformed / wrong-signature JWT → 401 with a
 *       {@code WWW-Authenticate: Bearer} challenge;</li>
 *   <li>insufficient-scope JWT stays 403 (never downgraded to 401) and carries no Bearer
 *       challenge;</li>
 *   <li>an API-key / no-credential 401 does NOT falsely advertise Bearer;</li>
 *   <li>the both-credentials 400 is a structured JSON {@code ApiError} that echoes neither
 *       credential.</li>
 * </ul>
 */
class AuthResponseProtocolIntegrationTest extends AbstractJwtEnabledTest {

    @Autowired
    private MockMvcTester mvc;

    private MockHttpServletResponse getWithBearer(String token) {
        return mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(token)).exchange().getResponse();
    }

    // ---- item 1: WWW-Authenticate: Bearer on invalid tokens -----------------------------

    @Test
    void expiredToken_401_withBearerChallenge() {
        MockHttpServletResponse r = getWithBearer(JWT.expiredToken("audit.read"));
        assertThat(r.getStatus()).isEqualTo(401);
        assertThat(r.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer");
    }

    @Test
    void malformedToken_401_withBearerChallenge() {
        MockHttpServletResponse r = getWithBearer(JWT.malformedToken());
        assertThat(r.getStatus()).isEqualTo(401);
        assertThat(r.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer");
    }

    @Test
    void wrongSignatureToken_401_withBearerChallenge() {
        MockHttpServletResponse r = getWithBearer(JWT.wrongSignatureToken("audit.read"));
        assertThat(r.getStatus()).isEqualTo(401);
        assertThat(r.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer");
    }

    @Test
    void bearerChallenge_neverContainsTheToken() {
        String token = JWT.expiredToken("audit.read");
        String challenge = getWithBearer(token).getHeader(HttpHeaders.WWW_AUTHENTICATE);
        // The RFC 6750 challenge may name the error reason, but never the token itself.
        assertThat(challenge).doesNotContain(token);
        for (String part : token.split("\\.")) {
            assertThat(challenge).doesNotContain(part);
        }
    }

    // ---- item 2: insufficient scope stays 403 (no Bearer challenge) ----------------------

    @Test
    void insufficientScope_stays403_noBearerChallenge() {
        // write scope, but GET /events requires read/admin → 403, not 401.
        MockHttpServletResponse r = mvc.get().uri("/api/v1/audit/events")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken("audit.write")))
                .exchange().getResponse();
        assertThat(r.getStatus()).isEqualTo(403);
        assertThat(r.getHeader(HttpHeaders.WWW_AUTHENTICATE)).isNull();
    }

    @Test
    void noScope_stays403_noBearerChallenge() {
        MockHttpServletResponse r = getWithBearer(JWT.validToken());
        assertThat(r.getStatus()).isEqualTo(403);
        assertThat(r.getHeader(HttpHeaders.WWW_AUTHENTICATE)).isNull();
    }

    // ---- item 3: API-key / no-credential 401 does not advertise Bearer -------------------

    @Test
    void noCredential_401_doesNotAdvertiseBearer() {
        MockHttpServletResponse r = mvc.get().uri("/api/v1/audit/verify").exchange().getResponse();
        assertThat(r.getStatus()).isEqualTo(401);
        String challenge = r.getHeader(HttpHeaders.WWW_AUTHENTICATE);
        assertThat(challenge == null || !challenge.contains("Bearer")).isTrue();
    }

    @Test
    void unknownApiKey_401_doesNotAdvertiseBearer() {
        MockHttpServletResponse r = mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "not-a-real-key").exchange().getResponse();
        assertThat(r.getStatus()).isEqualTo(401);
        String challenge = r.getHeader(HttpHeaders.WWW_AUTHENTICATE);
        assertThat(challenge == null || !challenge.contains("Bearer")).isTrue();
    }

    // ---- item 4: both-credentials 400 is a safe JSON ApiError ----------------------------

    @Test
    void bothCredentials_400_jsonApiError_noCredentialEchoed() throws Exception {
        String token = JWT.validToken("audit.read");
        MockHttpServletResponse r = mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(token))
                .header("X-API-Key", "test-compliance-key")
                .exchange().getResponse();

        assertThat(r.getStatus()).isEqualTo(400);
        assertThat(r.getContentType()).startsWith("application/json");
        String body = r.getContentAsString(StandardCharsets.UTF_8);
        // Structured ApiError shape.
        assertThat(body).contains("\"status\":400").contains("\"error\":\"Bad Request\"")
                .contains("\"message\":");
        // Neither credential is echoed.
        assertThat(body).doesNotContain(token).doesNotContain("test-compliance-key");
    }
}
