package com.raghavendra.audit.common.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Domain metrics for the audit-log service. Thin wrapper over Micrometer's {@link MeterRegistry}
 * with a fixed set of counters and <strong>bounded, low-cardinality tags only</strong>.
 *
 * <h2>Metric families (dotted names; Prometheus translates to {@code audit_*_total})</h2>
 * <ul>
 *   <li>{@code audit.events.appended}      — tag {@code result}=success|failure</li>
 *   <li>{@code audit.append.failures}      — dedicated failure counter (no tags)</li>
 *   <li>{@code audit.chain.verifications}  — tag {@code result}=intact|broken|failure</li>
 *   <li>{@code audit.redactions}           — tag {@code result}=success|failure</li>
 *   <li>{@code audit.archive.operations}   — tag {@code result}=success|failure</li>
 *   <li>{@code audit.export.operations}    — tag {@code result}=success|failure</li>
 *   <li>{@code audit.authentication.attempts} — tags {@code result}=success|failure,
 *       {@code method}=api_key|jwt|none|ambiguous, {@code reason} (fixed enum)</li>
 * </ul>
 *
 * <h2>Tag discipline</h2>
 * Tags are drawn ONLY from the enums below. Identifiers and free text are NEVER used as tags —
 * specifically never actorId, accountId, eventId, sequenceNumber, resourceId, API-key id, JWT
 * subject/fingerprint, requestId, or an exception message. This keeps the time-series cardinality
 * bounded and prevents sensitive values leaking into metric labels.
 *
 * <h2>Transactional success</h2>
 * For operations whose success must reflect a COMMITTED transaction (append, redaction, archive),
 * call {@link #incrementAfterCommit(Runnable)} from within the transaction; the counter fires only
 * in {@link TransactionSynchronization#afterCommit()}. A rollback therefore never counts a success.
 */
@Component
public class AuditMetrics {

    /** Generic success/failure result tag. */
    public enum Result {
        SUCCESS("success"), FAILURE("failure"), INTACT("intact"), BROKEN("broken");

        private final String tag;

        Result(String tag) {
            this.tag = tag;
        }

        public String tag() {
            return tag;
        }
    }

    /** Authentication mechanism tag. */
    public enum Method {
        API_KEY("api_key"), JWT("jwt"), NONE("none"), AMBIGUOUS("ambiguous");

        private final String tag;

        Method(String tag) {
            this.tag = tag;
        }

        public String tag() {
            return tag;
        }
    }

    /** Fixed set of authentication reasons (bounded — never free text). */
    public enum AuthReason {
        VALID_KEY("valid-key"), UNKNOWN_KEY("unknown-key"),
        VALID_TOKEN("valid-token"), INVALID_TOKEN("invalid-token"),
        BOTH_CREDENTIALS("both-credentials"), NO_CREDENTIAL("no-credential");

        private final String tag;

        AuthReason(String tag) {
            this.tag = tag;
        }

        public String tag() {
            return tag;
        }
    }

    private final MeterRegistry registry;

    public AuditMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    // ---- append ------------------------------------------------------------------------

    /** Increment appended{result=success} — call AFTER commit via {@link #incrementAfterCommit}. */
    public void appendedSuccess() {
        counter("audit.events.appended", "result", Result.SUCCESS.tag()).increment();
    }

    /** Increment a failed append (both the tagged family and the dedicated failure counter). */
    public void appendFailure() {
        counter("audit.events.appended", "result", Result.FAILURE.tag()).increment();
        Counter.builder("audit.append.failures").register(registry).increment();
    }

    // ---- verification ------------------------------------------------------------------

    /** Record a chain verification result: intact or broken (a completed run). */
    public void verification(boolean intact) {
        counter("audit.chain.verifications", "result",
                (intact ? Result.INTACT : Result.BROKEN).tag()).increment();
    }

    /** Record a verification that threw before producing a result (execution error). */
    public void verificationFailure() {
        counter("audit.chain.verifications", "result", Result.FAILURE.tag()).increment();
    }

    // ---- redaction / archive / export --------------------------------------------------

    public void redactionSuccess() {
        counter("audit.redactions", "result", Result.SUCCESS.tag()).increment();
    }

    public void redactionFailure() {
        counter("audit.redactions", "result", Result.FAILURE.tag()).increment();
    }

    public void archiveSuccess() {
        counter("audit.archive.operations", "result", Result.SUCCESS.tag()).increment();
    }

    public void archiveFailure() {
        counter("audit.archive.operations", "result", Result.FAILURE.tag()).increment();
    }

    public void exportSuccess() {
        counter("audit.export.operations", "result", Result.SUCCESS.tag()).increment();
    }

    public void exportFailure() {
        counter("audit.export.operations", "result", Result.FAILURE.tag()).increment();
    }

    // ---- authentication ----------------------------------------------------------------

    /** Record one authentication attempt with bounded result/method/reason tags. */
    public void authentication(Result result, Method method, AuthReason reason) {
        Counter.builder("audit.authentication.attempts")
                .tag("result", result.tag())
                .tag("method", method.tag())
                .tag("reason", reason.tag())
                .register(registry)
                .increment();
    }

    // ---- transaction-commit helper -----------------------------------------------------

    /**
     * Run {@code onCommit} only if/when the current transaction commits. If there is no active
     * transaction synchronization, the action runs immediately (best effort). Use this for success
     * counters that must not fire on rollback.
     */
    public void incrementAfterCommit(Runnable onCommit) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    onCommit.run();
                }
            });
        } else {
            onCommit.run();
        }
    }

    private Counter counter(String name, String tagKey, String tagValue) {
        return Counter.builder(name).tag(tagKey, tagValue).register(registry);
    }
}
