package com.raghavendra.audit.event;

import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * HTTP-level integration tests for the append write API (POST /api/v1/audit/events) using
 * {@link MockMvcTester}. Runs against a real PostgreSQL 16 via Testcontainers.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class AuditEventAppendIntegrationTest {

    @Autowired
    private MockMvcTester mvc;

    @Autowired
    private AuditEventRepository eventRepository;

    @Autowired
    private AuditChainHeadRepository chainHeadRepository;

    @BeforeEach
    void resetChain() {
        eventRepository.deleteAll();
        chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .ifPresent(h -> {
                    h.resetToEmpty(OffsetDateTime.now());
                    chainHeadRepository.save(h);
                });
    }

    private static final String VALID_BODY = """
            {
              "eventType": "USER_LOGIN",
              "actorId": "actor-1",
              "actorType": "USER",
              "resourceType": "CLIENT_ACCOUNT",
              "resourceId": "acct-1",
              "outcome": "SUCCESS",
              "payload": {"channel": "WEB"}
            }
            """;

    // ---- append success ----------------------------------------------------------------

    @Test
    void append_firstEvent_isGenesis_andReturns201() {
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(VALID_BODY))
                .hasStatus(HttpStatus.CREATED)
                .bodyJson()
                .extractingPath("$.sequenceNumber").isEqualTo(1);

        assertThat(mvc.post().uri("/api/v1/audit/events") // second, to check body of one
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(VALID_BODY))
                .hasStatus(HttpStatus.CREATED)
                .bodyJson()
                .extractingPath("$.previousHash").isNotNull(); // links to genesis

        assertThat(eventRepository.count()).isEqualTo(2);
    }

    @Test
    void append_genesis_hasNullPreviousHash_and64CharContentHash() {
        var result = mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(VALID_BODY);
        assertThat(result).hasStatus(HttpStatus.CREATED)
                .bodyJson().extractingPath("$.previousHash").isNull();
        assertThat(result).bodyJson()
                .extractingPath("$.contentHash").asString().hasSize(64);
    }

    @Test
    void append_persistsMicrosecondNormalizedTimestamp() {
        String body = """
                {
                  "eventType": "USER_LOGIN", "actorId": "a", "actorType": "USER",
                  "resourceType": "CLIENT_ACCOUNT", "resourceId": "r", "outcome": "SUCCESS",
                  "eventTimestamp": "2026-08-18T10:15:30.123456789Z"
                }
                """;
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(body))
                .hasStatus(HttpStatus.CREATED);

        var saved = eventRepository.findAll().get(0);
        // µs-truncated: nanos are a whole number of microseconds, and the sub-µs part is gone.
        assertThat(saved.getEventTimestamp().getNano() % 1000).isZero();
        assertThat(saved.getEventTimestamp().getNano()).isEqualTo(123456000);
    }

    // ---- validation (400) --------------------------------------------------------------

    @Test
    void append_missingRequiredField_returns400_andPersistsNothing() {
        String body = """
                { "eventType": "USER_LOGIN", "actorType": "USER",
                  "resourceType": "CLIENT_ACCOUNT", "resourceId": "r", "outcome": "SUCCESS" }
                """; // actorId missing
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content(body))
                .hasStatus(HttpStatus.BAD_REQUEST);
        assertThat(eventRepository.count()).isZero();
    }

    @Test
    void append_malformedJson_returns400() {
        assertThat(mvc.post().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON).content("{ not json "))
                .hasStatus(HttpStatus.BAD_REQUEST);
    }

    // ---- append-only: no update/delete endpoint ----------------------------------------

    @Test
    void collection_doesNotExposeUpdateOrDelete() {
        // With a valid WRITER key, PUT/DELETE still have no handler → 4xx (405/404), proving
        // the collection is append-only (not merely blocked by auth).
        assertThat(mvc.put().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")).hasStatus4xxClientError();
        assertThat(mvc.delete().uri("/api/v1/audit/events")
                .header("X-API-Key", "test-writer-key")).hasStatus4xxClientError();
    }
}
