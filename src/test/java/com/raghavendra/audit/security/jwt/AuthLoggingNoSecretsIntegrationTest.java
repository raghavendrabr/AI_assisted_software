package com.raghavendra.audit.security.jwt;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves that no credential material (the raw JWT, the API key, or any digest) appears in the
 * authentication logs or in HTTP responses, across success and failure paths. Captures the root
 * logger with an in-memory appender and inspects every formatted message.
 */
class AuthLoggingNoSecretsIntegrationTest extends AbstractJwtEnabledTest {

    @Autowired
    private MockMvcTester mvc;

    private ListAppender<ILoggingEvent> appender;
    private Logger root;

    @BeforeEach
    void attachAppender() {
        root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        appender = new ListAppender<>();
        appender.start();
        root.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        if (root != null && appender != null) {
            root.detachAppender(appender);
        }
    }

    private String allLogs() {
        StringBuilder sb = new StringBuilder();
        for (ILoggingEvent e : appender.list) {
            sb.append(e.getFormattedMessage()).append('\n');
        }
        return sb.toString();
    }

    @Test
    void validJwt_success_logsNoTokenMaterial() throws Exception {
        String token = JWT.validToken("audit.read");
        String response = mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(token))
                .exchange().getResponse().getContentAsString(StandardCharsets.UTF_8);

        String logs = allLogs();
        // The raw token (and its parts) must never be logged or echoed.
        assertThat(logs).doesNotContain(token);
        assertThat(response).doesNotContain(token);
        for (String part : token.split("\\.")) {
            assertThat(logs).doesNotContain(part);
        }
        // JWT success is logged with a subject FINGERPRINT, never the raw subject text.
        assertThat(logs).contains("method=JWT").contains("principal=jwt:");
        assertThat(logs).doesNotContain("subject-123"); // the raw JWT subject is never logged
    }

    @Test
    void invalidJwt_failure_logsNoTokenMaterial() throws Exception {
        String token = JWT.wrongSignatureToken("audit.read");
        String response = mvc.get().uri("/api/v1/audit/verify")
                .header(HttpHeaders.AUTHORIZATION, bearer(token))
                .exchange().getResponse().getContentAsString(StandardCharsets.UTF_8);

        String logs = allLogs();
        assertThat(logs).doesNotContain(token);
        assertThat(response).doesNotContain(token);
    }

    @Test
    void apiKeySuccess_logsKeyId_notTheKey() throws Exception {
        String response = mvc.get().uri("/api/v1/audit/verify")
                .header("X-API-Key", "test-compliance-key")
                .exchange().getResponse().getContentAsString(StandardCharsets.UTF_8);

        String logs = allLogs();
        // The key value must never appear; the non-secret key id may.
        assertThat(logs).doesNotContain("test-compliance-key");
        assertThat(response).doesNotContain("test-compliance-key");
        assertThat(logs).contains("compliance_reader-key"); // sanitized key id is logged
    }
}
