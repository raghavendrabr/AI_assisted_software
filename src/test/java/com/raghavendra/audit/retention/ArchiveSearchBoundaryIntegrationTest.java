package com.raghavendra.audit.retention;

import com.raghavendra.audit.event.api.AppendEventRequest;
import com.raghavendra.audit.event.application.AuditEventAppendService;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.amendment.domain.AuditAmendmentRepository;
import com.raghavendra.audit.retention.domain.ArchiveManifestRepository;
import com.raghavendra.audit.retention.domain.AuditEventArchiveRepository;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Search & compliance across the archive boundary: default excludes archived; includeArchived
 * merges active + archived once each ordered by sequence; cursor pagination is correct across the
 * boundary; the default compliance report still includes an archived access exactly once.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class ArchiveSearchBoundaryIntegrationTest {

    @Autowired private MockMvcTester mvc;
    @Autowired private AuditEventAppendService appendService;
    @Autowired private ArchiveService archiveService;
    @Autowired private AuditEventRepository eventRepository;
    @Autowired private AuditEventArchiveRepository archiveRepository;
    @Autowired private ArchiveManifestRepository manifestRepository;
    @Autowired private AuditAmendmentRepository amendmentRepository;
    @Autowired private AuditChainHeadRepository chainHeadRepository;

    @BeforeEach
    void reset() {
        amendmentRepository.deleteAll();
        manifestRepository.deleteAll();
        archiveRepository.deleteAll();
        eventRepository.deleteAll();
        chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .ifPresent(h -> { h.resetToEmpty(OffsetDateTime.now()); chainHeadRepository.save(h); });
    }

    private OffsetDateTime T(int m) {
        return OffsetDateTime.of(2026, 8, 1, 10, m, 0, 0, ZoneOffset.UTC);
    }

    private void appendAt(OffsetDateTime ts) {
        appendService.append(new AppendEventRequest(
                "CLIENT_ACCOUNT_VIEWED", "emp", "EMPLOYEE", "CLIENT_ACCOUNT", "acct-1",
                "SUCCESS", null, null, null, ts), UUID.randomUUID());
    }

    private org.springframework.test.web.servlet.assertj.MockMvcTester.MockMvcRequestBuilder get(String uri) {
        return mvc.get().uri(uri).header("X-API-Key", "test-compliance-key");
    }

    @Test
    void defaultSearchExcludesArchived_includeArchivedMergesOnceEach() {
        for (int i = 0; i < 5; i++) {
            appendAt(T(i));            // sequences 1..5
        }
        archiveService.archiveOlderThan(T(3), "admin-1"); // archives 1,2,3; active 4,5

        // Default: active only (4,5).
        assertThat(get("/api/v1/audit/events?limit=100"))
                .hasStatusOk()
                .bodyJson().extractingPath("$.events").asArray().hasSize(2);

        // includeArchived: all 5, once each, ordered by sequence.
        var all = get("/api/v1/audit/events?limit=100&includeArchived=true");
        assertThat(all).hasStatusOk()
                .bodyJson().extractingPath("$.events").asArray().hasSize(5);
        assertThat(all).bodyJson().extractingPath("$.events[0].sequenceNumber").isEqualTo(1);
        assertThat(all).bodyJson().extractingPath("$.events[4].sequenceNumber").isEqualTo(5);
        // Archived flag present.
        assertThat(all).bodyJson().extractingPath("$.events[0].archived").isEqualTo(true);
        assertThat(all).bodyJson().extractingPath("$.events[4].archived").isEqualTo(false);
    }

    @Test
    void cursorPagination_isCorrectAcrossArchiveBoundary() {
        for (int i = 0; i < 6; i++) {
            appendAt(T(i));            // 1..6
        }
        archiveService.archiveOlderThan(T(3), "admin-1"); // archives 1,2,3

        // Page across the boundary with includeArchived, limit 2: expect 1,2 | 3,4 | 5,6.
        var p1 = get("/api/v1/audit/events?includeArchived=true&limit=2");
        assertThat(p1).bodyJson().extractingPath("$.events[0].sequenceNumber").isEqualTo(1);
        assertThat(p1).bodyJson().extractingPath("$.events[1].sequenceNumber").isEqualTo(2);
        assertThat(p1).bodyJson().extractingPath("$.nextCursor").isEqualTo(2);

        var p2 = get("/api/v1/audit/events?includeArchived=true&limit=2&cursor=2");
        assertThat(p2).bodyJson().extractingPath("$.events[0].sequenceNumber").isEqualTo(3); // archive
        assertThat(p2).bodyJson().extractingPath("$.events[1].sequenceNumber").isEqualTo(4); // active
        assertThat(p2).bodyJson().extractingPath("$.nextCursor").isEqualTo(4);

        var p3 = get("/api/v1/audit/events?includeArchived=true&limit=2&cursor=4");
        assertThat(p3).bodyJson().extractingPath("$.events[0].sequenceNumber").isEqualTo(5);
        assertThat(p3).bodyJson().extractingPath("$.events[1].sequenceNumber").isEqualTo(6);
        assertThat(p3).bodyJson().extractingPath("$.nextCursor").isNull();
    }

    @Test
    void complianceReport_afterArchival_includesAccessExactlyOnce() {
        appendAt(T(0));                // one client-account access, sequence 1
        appendAt(T(5));                // keep something active so the prefix stops
        archiveService.archiveOlderThan(T(3), "admin-1"); // archives sequence 1

        // Default compliance report (includeArchived defaults true) → the archived access appears once.
        var report = get("/api/v1/compliance/access-report");
        assertThat(report).hasStatusOk()
                .bodyJson().extractingPath("$.entries").asArray().hasSize(2); // both accesses, none duplicated
        // The archived one is present exactly once (sequence 1).
        assertThat(report).bodyJson()
                .extractingPath("$.entries[0].sequenceNumber").isEqualTo(1);
    }
}
