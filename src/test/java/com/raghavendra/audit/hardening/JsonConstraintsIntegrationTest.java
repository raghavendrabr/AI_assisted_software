package com.raghavendra.audit.hardening;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies Jackson {@code StreamReadConstraints} enforcement on the request mapper. The bounds are
 * lowered for this test so violations are easy to construct. Excessive nesting depth, string
 * length, or number length must be rejected with a safe 400 whose body never echoes the payload.
 *
 * <p>The body stays comfortably under the size cap so we prove the JSON constraints trip
 * independently of the byte-size limit.
 */
@SpringBootTest(properties = {
        "audit.limits.max-request-bytes=1048576",   // large, so size is not the trigger
        "audit.limits.max-json-depth=8",
        "audit.limits.max-json-string-length=64",
        "audit.limits.max-json-number-length=16"
})
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class JsonConstraintsIntegrationTest {

    @Autowired
    private MockMvcTester mvc;

    private static final String MARKER = "ECHO_MARKER_7c1d";

    private static String base(String payload) {
        return "{\"eventType\":\"USER_LOGIN\",\"actorId\":\"a\",\"actorType\":\"USER\","
                + "\"resourceType\":\"CLIENT_ACCOUNT\",\"resourceId\":\"acct-1\",\"outcome\":\"SUCCESS\","
                + "\"payload\":" + payload + "}";
    }

    @Test
    void excessiveNestingDepth_isRejected_400() {
        StringBuilder open = new StringBuilder();
        StringBuilder close = new StringBuilder();
        for (int i = 0; i < 40; i++) {         // far beyond depth 8
            open.append("{\"a\":");
            close.append("}");
        }
        String deep = open.append("1").append(close).toString();
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(base(deep))).hasStatus(400);
    }

    @Test
    void excessiveStringLength_isRejected_400() {
        String longStr = MARKER + "y".repeat(500); // > 64 chars
        String payload = "{\"note\":\"" + longStr + "\"}";
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(base(payload))).hasStatus(400);
    }

    @Test
    void excessiveNumberLength_isRejected_400() {
        String bigNumber = "1".repeat(64); // > 16 chars
        String payload = "{\"n\":" + bigNumber + "}";
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(base(payload))).hasStatus(400);
    }

    @Test
    void constraintViolation_neverEchoesPayload() throws Exception {
        String longStr = MARKER + "y".repeat(500);
        String payload = "{\"note\":\"" + longStr + "\"}";
        String responseBody = mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(base(payload))
                .exchange().getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(responseBody).doesNotContain(MARKER);
    }
}
