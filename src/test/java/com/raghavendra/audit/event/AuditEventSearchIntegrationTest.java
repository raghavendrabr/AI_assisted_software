package com.raghavendra.audit.event;

import com.raghavendra.audit.event.api.AppendEventRequest;
import com.raghavendra.audit.event.application.AuditEventAppendService;
import com.raghavendra.audit.event.application.AuditEventQueryService;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Search/pagination integration tests for GET /api/v1/audit/events. Real PostgreSQL 16.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class AuditEventSearchIntegrationTest {

    @Autowired private MockMvcTester mvc;
    @Autowired private AuditEventAppendService appendService;
    @Autowired private AuditEventRepository eventRepository;
    @Autowired private AuditChainHeadRepository chainHeadRepository;

    @BeforeEach
    void reset() {
        eventRepository.deleteAll();
        chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .ifPresent(h -> { h.resetToEmpty(OffsetDateTime.now()); chainHeadRepository.save(h); });
    }

    private void append(String actorId, String resourceId, String eventType) {
        appendService.append(new AppendEventRequest(
                eventType, actorId, "USER", "CLIENT_ACCOUNT", resourceId,
                "SUCCESS", null, null, null), UUID.randomUUID());
    }

    /** GET with a COMPLIANCE_READER key (search requires COMPLIANCE_READER or ADMIN). */
    private org.springframework.test.web.servlet.assertj.MockMvcTester.MockMvcRequestBuilder get(String uri) {
        return mvc.get().uri(uri).header("X-API-Key", "test-compliance-key");
    }

    @Test
    void filterByActorId_returnsOnlyMatching() {
        append("alice", "acct-1", "USER_LOGIN");
        append("bob", "acct-1", "USER_LOGIN");
        append("alice", "acct-2", "RECORD_UPDATED");

        assertThat(get("/api/v1/audit/events?actorId=alice"))
                .hasStatusOk()
                .bodyJson()
                .extractingPath("$.events").asArray().hasSize(2);
    }

    @Test
    void filterByResourceAndEventType_combinesWithAnd() {
        append("alice", "acct-1", "USER_LOGIN");
        append("alice", "acct-2", "USER_LOGIN");
        append("alice", "acct-1", "RECORD_UPDATED");

        assertThat(get("/api/v1/audit/events?resourceId=acct-1&eventType=USER_LOGIN"))
                .hasStatusOk()
                .bodyJson()
                .extractingPath("$.events").asArray().hasSize(1);
    }

    @Test
    void pagination_isCursorBased_andStable() {
        for (int i = 0; i < 5; i++) {
            append("alice", "acct-1", "USER_LOGIN");
        }

        // First page of 2.
        var page1 = get("/api/v1/audit/events?limit=2");
        assertThat(page1).hasStatusOk()
                .bodyJson().extractingPath("$.events").asArray().hasSize(2);
        assertThat(page1).bodyJson().extractingPath("$.nextCursor").isEqualTo(2);

        // Second page after cursor=2 → sequences 3,4.
        var page2 = get("/api/v1/audit/events?limit=2&cursor=2");
        assertThat(page2).hasStatusOk()
                .bodyJson().extractingPath("$.events[0].sequenceNumber").isEqualTo(3);
        assertThat(page2).bodyJson().extractingPath("$.nextCursor").isEqualTo(4);

        // Last page after cursor=4 → sequence 5, nextCursor null (not full).
        var page3 = get("/api/v1/audit/events?limit=2&cursor=4");
        assertThat(page3).hasStatusOk()
                .bodyJson().extractingPath("$.events").asArray().hasSize(1);
        assertThat(page3).bodyJson().extractingPath("$.nextCursor").isNull();
    }

    @Test
    void limit_isBoundedByServerMax() {
        append("alice", "acct-1", "USER_LOGIN");
        // Requesting a huge limit must be clamped to MAX_LIMIT and not error.
        assertThat(get("/api/v1/audit/events?limit=100000"))
                .hasStatusOk()
                .bodyJson().extractingPath("$.limit").isEqualTo(AuditEventQueryService.MAX_LIMIT);
    }

    @Test
    void exactLimitFinalPage_hasNoNextCursor() {
        // Exactly `limit` rows remain: the limit+1 probe finds no extra row → nextCursor null.
        for (int i = 0; i < 4; i++) {
            append("alice", "acct-1", "USER_LOGIN");
        }
        var page = get("/api/v1/audit/events?limit=2&cursor=2"); // remaining: seq 3,4 exactly
        assertThat(page).hasStatusOk()
                .bodyJson().extractingPath("$.events").asArray().hasSize(2);
        assertThat(page).bodyJson().extractingPath("$.nextCursor").isNull();
    }

    @Test
    void pageWithOneAdditionalRow_hasNextCursor() {
        // 3 rows remain but limit is 2: the extra row proves another page → nextCursor set.
        for (int i = 0; i < 3; i++) {
            append("alice", "acct-1", "USER_LOGIN");
        }
        var page = get("/api/v1/audit/events?limit=2");
        assertThat(page).hasStatusOk()
                .bodyJson().extractingPath("$.events").asArray().hasSize(2);
        assertThat(page).bodyJson().extractingPath("$.nextCursor").isEqualTo(2);
    }

    @Test
    void nonPositiveLimit_returns400() {
        assertThat(get("/api/v1/audit/events?limit=0")).hasStatus(400);
        assertThat(get("/api/v1/audit/events?limit=-5")).hasStatus(400);
    }

    @Test
    void fromNotBeforeTo_returns400() {
        assertThat(get("/api/v1/audit/events"
                + "?from=2026-08-18T12:00:00Z&to=2026-08-18T10:00:00Z")).hasStatus(400);
        // Equal from/to is also invalid (from must be strictly before to).
        assertThat(get("/api/v1/audit/events"
                + "?from=2026-08-18T12:00:00Z&to=2026-08-18T12:00:00Z")).hasStatus(400);
    }
}
