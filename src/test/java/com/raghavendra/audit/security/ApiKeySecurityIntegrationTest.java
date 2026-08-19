package com.raghavendra.audit.security;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Enforces the endpoint authorization matrix. Missing/invalid key → 401; valid key with the
 * wrong role → 403; correct role → 2xx. The client only ever sends X-API-Key; the role is
 * resolved server-side.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class ApiKeySecurityIntegrationTest {

    @Autowired
    private MockMvcTester mvc;

    private static final String WRITE_BODY = """
            { "eventType":"USER_LOGIN","actorId":"a","actorType":"USER",
              "resourceType":"CLIENT_ACCOUNT","resourceId":"acct-1","outcome":"SUCCESS" }
            """;

    // ---- missing / invalid key → 401 ---------------------------------------------------

    @Test
    void noApiKey_isUnauthorized_401() {
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .contentType(MediaType.APPLICATION_JSON).content(WRITE_BODY)).hasStatus(401);
        assertThat(mvc.get().uri("/api/v1/audit/events")).hasStatus(401);
        assertThat(mvc.get().uri("/api/v1/audit/verify")).hasStatus(401);
        assertThat(mvc.get().uri("/api/v1/compliance/access-report")).hasStatus(401);
    }

    @Test
    void invalidApiKey_isUnauthorized_401() {
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "not-a-real-key")).hasStatus(401);
    }

    // ---- valid key, wrong role → 403 ---------------------------------------------------

    @Test
    void writerKey_cannotRead_403() {
        assertThat(mvc.get().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")).hasStatus(403);
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-writer-key")).hasStatus(403);
        assertThat(mvc.get().uri("/api/v1/compliance/access-report")
                .header("X-API-Key", "test-writer-key")).hasStatus(403);
    }

    @Test
    void complianceKey_cannotWrite_403() {
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-compliance-key")
                .contentType(MediaType.APPLICATION_JSON).content(WRITE_BODY)).hasStatus(403);
    }

    // ---- correct role → allowed --------------------------------------------------------

    @Test
    void writerKey_canWrite_201() {
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(WRITE_BODY)).hasStatus(201);
    }

    @Test
    void complianceKey_canReadAndVerify() {
        assertThat(mvc.get().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-compliance-key")).hasStatusOk();
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key")).hasStatusOk();
        assertThat(mvc.get().uri("/api/v1/compliance/access-report")
                .header("X-API-Key", "test-compliance-key")).hasStatusOk();
    }

    // ---- fail-closed default: an unlisted endpoint is denied even for ADMIN ------------

    @Test
    void unlistedEndpoint_isDenied_evenWithAdminKey() {
        // No authorization rule matches this path, so denyAll() applies. Even a valid ADMIN
        // key must NOT grant access — proving new endpoints are not accidentally public.
        assertThat(mvc.get().uri("/api/v1/audit/some-unlisted-endpoint")
                .header("X-API-Key", "test-admin-key")).hasStatus(403);
    }

    @Test
    void unlistedEndpoint_withoutKey_isUnauthorized_401() {
        assertThat(mvc.get().uri("/api/v1/audit/some-unlisted-endpoint")).hasStatus(401);
    }

    @Test
    void adminKey_canWriteReadVerifyAndReport() {
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-admin-key")
                .contentType(MediaType.APPLICATION_JSON).content(WRITE_BODY)).hasStatus(201);
        assertThat(mvc.get().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-admin-key")).hasStatusOk();
        assertThat(mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-admin-key")).hasStatusOk();
        assertThat(mvc.get().uri("/api/v1/compliance/access-report")
                .header("X-API-Key", "test-admin-key")).hasStatusOk();
    }
}
