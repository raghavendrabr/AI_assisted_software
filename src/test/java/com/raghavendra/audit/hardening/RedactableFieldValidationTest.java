package com.raghavendra.audit.hardening;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bean-Validation bounds on {@code redactableFields}: the list is capped in count, each entry is
 * capped in length, and each entry must match the allowed identifier syntax. All violations →
 * 400. A well-formed small list is accepted.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class RedactableFieldValidationTest {

    @Autowired
    private MockMvcTester mvc;

    private static String bodyWithRedactable(String redactableJsonArray) {
        return "{\"eventType\":\"USER_LOGIN\",\"actorId\":\"a\",\"actorType\":\"USER\","
                + "\"resourceType\":\"CLIENT_ACCOUNT\",\"resourceId\":\"acct-1\",\"outcome\":\"SUCCESS\","
                + "\"payload\":{\"accountNumber\":\"123\"},"
                + "\"redactableFields\":" + redactableJsonArray + "}";
    }

    @Test
    void tooManyRedactableFields_isRejected_400() {
        String many = IntStream.range(0, 65) // > 64
                .mapToObj(i -> "\"f" + i + "\"")
                .collect(Collectors.joining(",", "[", "]"));
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(bodyWithRedactable(many))).hasStatus(400);
    }

    @Test
    void overlongRedactableFieldPath_isRejected_400() {
        String longName = "\"" + "a".repeat(200) + "\""; // > 128 chars
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(bodyWithRedactable("[" + longName + "]"))).hasStatus(400);
    }

    @Test
    void illegalRedactableFieldSyntax_isRejected_400() {
        // Space and slash are outside the permitted [A-Za-z0-9_.-] set.
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(bodyWithRedactable("[\"bad name/../etc\"]"))).hasStatus(400);
    }

    @Test
    void wellFormedRedactableFields_isAccepted_201() {
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(bodyWithRedactable("[\"accountNumber\"]"))).hasStatus(201);
    }
}
