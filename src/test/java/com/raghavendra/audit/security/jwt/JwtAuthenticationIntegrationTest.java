package com.raghavendra.audit.security.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Dual-mode authentication with a REAL {@code NimbusJwtDecoder} and locally-signed tokens.
 * Exercises the full positive/negative token matrix plus the dual-credential rules.
 */
class JwtAuthenticationIntegrationTest extends AbstractJwtEnabledTest {

    @Autowired
    private MockMvcTester mvc;

    private static final String WRITE_BODY = """
            { "eventType":"USER_LOGIN","actorId":"a","actorType":"USER",
              "resourceType":"CLIENT_ACCOUNT","resourceId":"acct-1","outcome":"SUCCESS" }
            """;

    // ---- API key still works while JWT is enabled (dual-mode) --------------------------

    @Test
    void validApiKey_stillWorks_whenJwtEnabled() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key")).hasStatusOk();
    }

    // ---- valid JWT per trusted scope ---------------------------------------------------

    @Test
    void jwt_writeScope_canWrite() {
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken("audit.write")))
                .contentType(MediaType.APPLICATION_JSON).content(WRITE_BODY)).hasStatus(201);
    }

    @Test
    void jwt_readScope_canReadAndVerify() {
        assertThat(mvc.get().uri("/api/v1/audit/events")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken("audit.read")))).hasStatusOk();
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken("audit.read")))).hasStatusOk();
    }

    @Test
    void jwt_adminScope_canRedact() {
        // ADMIN scope reaches the redact endpoint (404/400 downstream is fine — authZ passed, not 401/403).
        assertThat(mvc.post().uri("/api/v1/audit/events/999999/redact")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken("audit.admin")))
                .contentType(MediaType.APPLICATION_JSON).content("{\"field\":\"x\"}"))
                .satisfies(r -> assertThat(r.getResponse().getStatus()).isNotIn(401, 403));
    }

    // ---- negative token cases ----------------------------------------------------------

    @Test
    void expiredToken_isUnauthorized_401() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.expiredToken("audit.read")))).hasStatus(401);
    }

    @Test
    void notYetValidToken_isUnauthorized_401() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.notYetValidToken("audit.read")))).hasStatus(401);
    }

    @Test
    void malformedToken_isUnauthorized_401() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.malformedToken()))).hasStatus(401);
    }

    @Test
    void wrongSignatureToken_isUnauthorized_401() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.wrongSignatureToken("audit.read")))).hasStatus(401);
    }

    @Test
    void disallowedAlgorithmToken_isUnauthorized_401() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.disallowedAlgorithmToken("audit.read")))).hasStatus(401);
    }

    @Test
    void wrongIssuerToken_isUnauthorized_401() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.wrongIssuerToken("audit.read")))).hasStatus(401);
    }

    @Test
    void wrongAudienceToken_isUnauthorized_401() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.wrongAudienceToken("audit.read")))).hasStatus(401);
    }

    // ---- scope / authority mapping -----------------------------------------------------

    @Test
    void missingScopes_isForbidden_403() {
        // Valid token, no scope at all → authenticated but no authority → 403.
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken()))).hasStatus(403);
    }

    @Test
    void insufficientScope_isForbidden_403() {
        // read scope cannot write → 403.
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken("audit.read")))
                .contentType(MediaType.APPLICATION_JSON).content(WRITE_BODY)).hasStatus(403);
    }

    @Test
    void rolesClaimOnly_grantsNothing_403() {
        // A client-supplied roles/authorities claim (no scope) must be ignored → 403.
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.rolesClaimOnlyToken()))).hasStatus(403);
    }

    @Test
    void unknownScopes_grantNoAuthority_403() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION,
                        bearer(JWT.tokenWithScopeString("some.other.scope openid profile")))).hasStatus(403);
    }

    // ---- dual-credential rules ---------------------------------------------------------

    @Test
    void bothCredentials_isRejected_400() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.validToken("audit.read")))
                .header("X-API-Key", "test-compliance-key")).hasStatus(400);
    }

    @Test
    void invalidBearer_doesNotFallBackToApiKey() {
        // Even though there is NO api key here, the key point is the reverse: with an invalid Bearer
        // present, the request must be 401 (JWT path), never silently succeeding. And with an api key
        // ALSO present it is 400 (both-credentials), tested above — so no fallback path exists.
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.expiredToken("audit.read")))).hasStatus(401);
    }
}
