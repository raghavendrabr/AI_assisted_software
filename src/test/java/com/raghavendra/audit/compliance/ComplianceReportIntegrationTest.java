package com.raghavendra.audit.compliance;

import com.raghavendra.audit.event.api.AppendEventRequest;
import com.raghavendra.audit.event.application.AuditEventAppendService;
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
 * Compliance access-report tests: covers successful AND denied client-account access, the
 * actor/account/outcome/time filters, exclusion of non-client-account events, and the tie-back
 * to the immutable record (contentHash present). Real PostgreSQL 16.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
class ComplianceReportIntegrationTest {

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

    private void access(String actor, String account, String outcome, String resourceType) {
        appendService.append(new AppendEventRequest(
                "CLIENT_ACCOUNT_VIEWED", actor, "EMPLOYEE", resourceType, account,
                outcome, "customer support", null, null, null), UUID.randomUUID());
    }

    private org.springframework.test.web.servlet.assertj.MockMvcTester.MockMvcRequestBuilder report(String query) {
        return mvc.get().uri("/api/v1/compliance/access-report" + query)
                .header("X-API-Key", "test-compliance-key");
    }

    @Test
    void report_includesSuccessfulAndDeniedAccess_toClientAccounts() {
        access("emp-1", "acct-1", "SUCCESS", "CLIENT_ACCOUNT");
        access("emp-2", "acct-1", "DENIED", "CLIENT_ACCOUNT");
        // A non-client-account event must be excluded from the report.
        access("emp-1", "order-9", "SUCCESS", "ORDER");

        assertThat(report(""))
                .hasStatusOk()
                .bodyJson().extractingPath("$.entries").asArray().hasSize(2);
    }

    @Test
    void report_filtersByOutcome_denied() {
        access("emp-1", "acct-1", "SUCCESS", "CLIENT_ACCOUNT");
        access("emp-2", "acct-1", "DENIED", "CLIENT_ACCOUNT");

        var denied = report("?outcome=DENIED");
        assertThat(denied).hasStatusOk()
                .bodyJson().extractingPath("$.entries").asArray().hasSize(1);
        assertThat(denied).bodyJson().extractingPath("$.entries[0].outcome").isEqualTo("DENIED");
        assertThat(denied).bodyJson().extractingPath("$.entries[0].actorId").isEqualTo("emp-2");
    }

    @Test
    void report_filtersByActorAndAccount() {
        access("emp-1", "acct-1", "SUCCESS", "CLIENT_ACCOUNT");
        access("emp-1", "acct-2", "SUCCESS", "CLIENT_ACCOUNT");
        access("emp-2", "acct-1", "SUCCESS", "CLIENT_ACCOUNT");

        assertThat(report("?actorId=emp-1&accountId=acct-1"))
                .hasStatusOk()
                .bodyJson().extractingPath("$.entries").asArray().hasSize(1);
    }

    @Test
    void report_entriesAreTiedToImmutableRecord() {
        access("emp-1", "acct-1", "SUCCESS", "CLIENT_ACCOUNT");
        var r = report("");
        assertThat(r).hasStatusOk()
                .bodyJson().extractingPath("$.entries[0].contentHash").asString().hasSize(64);
        assertThat(r).bodyJson().extractingPath("$.entries[0].accountId").isEqualTo("acct-1");
        assertThat(r).bodyJson().extractingPath("$.filters.clientAccountResourceType")
                .isEqualTo("CLIENT_ACCOUNT");
    }

    @Test
    void report_invalidTimeRange_returns400() {
        assertThat(report("?from=2026-08-18T12:00:00Z&to=2026-08-18T10:00:00Z")).hasStatus(400);
    }
}
