package com.raghavendra.audit.observability;

import com.raghavendra.audit.common.observability.AuditMetrics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AuditMetrics}: correct meter names, bounded tags, and the transaction-commit
 * helper. Uses a real {@link SimpleMeterRegistry} (no mocking).
 */
class AuditMetricsTest {

    private SimpleMeterRegistry registry;
    private AuditMetrics metrics;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new AuditMetrics(registry);
    }

    private double count(String name, String... tags) {
        Counter c = registry.find(name).tags(tags).counter();
        return c == null ? 0.0 : c.count();
    }

    @Test
    void appendFailure_incrementsFailureFamilies_notSuccess() {
        metrics.appendFailure();
        assertThat(count("audit.events.appended", "result", "failure")).isEqualTo(1.0);
        assertThat(count("audit.append.failures")).isEqualTo(1.0);
        assertThat(count("audit.events.appended", "result", "success")).isEqualTo(0.0);
    }

    @Test
    void verification_recordsIntactVsBroken() {
        metrics.verification(true);
        metrics.verification(false);
        metrics.verificationFailure();
        assertThat(count("audit.chain.verifications", "result", "intact")).isEqualTo(1.0);
        assertThat(count("audit.chain.verifications", "result", "broken")).isEqualTo(1.0);
        assertThat(count("audit.chain.verifications", "result", "failure")).isEqualTo(1.0);
    }

    @Test
    void redactionArchiveExport_successAndFailure() {
        metrics.redactionSuccess();
        metrics.redactionFailure();
        metrics.archiveSuccess();
        metrics.archiveFailure();
        metrics.exportSuccess();
        metrics.exportFailure();
        assertThat(count("audit.redactions", "result", "success")).isEqualTo(1.0);
        assertThat(count("audit.redactions", "result", "failure")).isEqualTo(1.0);
        assertThat(count("audit.archive.operations", "result", "success")).isEqualTo(1.0);
        assertThat(count("audit.archive.operations", "result", "failure")).isEqualTo(1.0);
        assertThat(count("audit.export.operations", "result", "success")).isEqualTo(1.0);
        assertThat(count("audit.export.operations", "result", "failure")).isEqualTo(1.0);
    }

    @Test
    void authentication_usesBoundedResultMethodReasonTags() {
        metrics.authentication(AuditMetrics.Result.SUCCESS, AuditMetrics.Method.API_KEY,
                AuditMetrics.AuthReason.VALID_KEY);
        assertThat(count("audit.authentication.attempts",
                "result", "success", "method", "api_key", "reason", "valid-key")).isEqualTo(1.0);
    }

    @Test
    void incrementAfterCommit_runsImmediately_whenNoTransaction() {
        // No active transaction synchronization → runs immediately (best effort).
        metrics.incrementAfterCommit(metrics::appendedSuccess);
        assertThat(count("audit.events.appended", "result", "success")).isEqualTo(1.0);
    }

    @Test
    void meterTags_areBounded_neverIdentifiersOrFreeText() {
        // Drive every family once and assert the only tag keys used are the bounded set.
        metrics.appendedSuccess();
        metrics.appendFailure();
        metrics.verification(true);
        metrics.redactionSuccess();
        metrics.archiveSuccess();
        metrics.exportSuccess();
        metrics.authentication(AuditMetrics.Result.FAILURE, AuditMetrics.Method.JWT,
                AuditMetrics.AuthReason.INVALID_TOKEN);

        Set<String> forbidden = Set.of("actorId", "accountId", "eventId", "sequenceNumber",
                "resourceId", "keyId", "subject", "fingerprint", "requestId", "message", "exception");
        Set<String> allowedKeys = Set.of("result", "method", "reason");

        for (Meter m : registry.getMeters()) {
            if (!m.getId().getName().startsWith("audit.")) {
                continue;
            }
            Set<String> keys = m.getId().getTags().stream().map(Tag::getKey).collect(Collectors.toSet());
            assertThat(keys).as("tags on %s", m.getId().getName()).isSubsetOf(allowedKeys);
            assertThat(keys).doesNotContainAnyElementsOf(forbidden);
        }
    }
}
