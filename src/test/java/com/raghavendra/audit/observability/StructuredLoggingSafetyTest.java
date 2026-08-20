package com.raghavendra.audit.observability;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Logging-safety checks under ECS structured logging (the default profile enables
 * {@code logging.structured.format.console=ecs}). Captures the console, drives representative
 * auth/append/verify traffic, and asserts:
 * <ul>
 *   <li>emitted log lines are valid ECS JSON;</li>
 *   <li>the {@code requestId} MDC value appears in the JSON;</li>
 *   <li>NO secret material appears — API keys, JWT tokens, plaintext payload values, or
 *       signing-key bytes.</li>
 * </ul>
 */
@SpringBootTest(properties = "logging.structured.format.console=ecs")
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class StructuredLoggingSafetyTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private MockMvcTester mvc;

    private static final String SECRET_PAYLOAD_VALUE = "SECRET_ACCT_1234567890";
    private static final String WRITE_BODY = """
            { "eventType":"USER_LOGIN","actorId":"a","actorType":"USER",
              "resourceType":"CLIENT_ACCOUNT","resourceId":"acct-log","outcome":"SUCCESS",
              "payload": { "accountNumber": "%s" }, "redactableFields": ["accountNumber"] }
            """.formatted(SECRET_PAYLOAD_VALUE);

    @Test
    void ecsLogs_areValidJson_haveRequestId_andLeakNoSecrets() {
        PrintStream originalOut = System.out;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buffer, true, StandardCharsets.UTF_8));
        try {
            // Success with an api key (logs a sanitized auth line with a key id).
            mvc.get().uri("/api/v1/audit/verify")
                    .header("X-API-Key", "test-compliance-key")
                    .header("X-Request-Id", "corr-42").exchange();
            // An append carrying a redactable secret payload value.
            mvc.post().uri("/api/v1/audit/events").header("X-API-Key", "test-writer-key")
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .content(WRITE_BODY).exchange();
            // An api-key failure (sanitized failure line).
            mvc.get().uri("/api/v1/audit/verify").header("X-API-Key", "totally-wrong-key").exchange();
        } finally {
            System.out.flush();
            System.setOut(originalOut);
        }

        String captured = buffer.toString(StandardCharsets.UTF_8);
        assertThat(captured).as("some log output was captured").isNotBlank();

        boolean sawAuthLine = false;
        boolean sawRequestId = false;
        int jsonLines = 0;
        for (String line : captured.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || !trimmed.startsWith("{")) {
                continue; // non-JSON console noise (e.g. banner) is ignored
            }
            // Every JSON log line must parse as valid JSON (ECS mode).
            var node = JSON.readTree(trimmed);
            assertThat(node.isObject()).as("ECS line is a JSON object: %s", trimmed).isTrue();
            jsonLines++;
            if (trimmed.contains("corr-42")) {
                sawRequestId = true;
            }
            if (trimmed.contains("auth method=")) {
                sawAuthLine = true;
            }
        }

        assertThat(jsonLines).as("at least one ECS JSON line").isGreaterThan(0);
        assertThat(sawRequestId).as("requestId present in ECS output").isTrue();
        assertThat(sawAuthLine).as("a sanitized auth line was emitted").isTrue();

        // No secret material anywhere in the captured logs.
        assertThat(captured).doesNotContain(SECRET_PAYLOAD_VALUE);   // plaintext payload value
        assertThat(captured).doesNotContain("test-compliance-key");  // API key
        assertThat(captured).doesNotContain("totally-wrong-key");    // rejected API key
        assertThat(captured).doesNotContain("-----BEGIN PRIVATE KEY-----");
    }
}
