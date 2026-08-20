package com.raghavendra.audit.verify;

import com.raghavendra.audit.common.observability.AuditMetrics;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Chain verification endpoint.
 *
 * <p>{@code GET /api/v1/audit/verify} walks the full chain and reports whether it is intact.
 * When broken, the body identifies the first inconsistent record and the violation type.
 *
 * <p>Always returns HTTP 200: verification "ran successfully" regardless of the chain's health.
 * A broken chain is a valid, expected answer (the assignment validates by tampering a record
 * and re-verifying), not an HTTP error. Callers inspect {@code intact} in the body.
 *
 * <p>Metrics ({@code audit.chain.verifications}) are recorded here, at the single call site:
 * {@code result=intact|broken} for a completed run, and {@code result=failure} if verification
 * threw an execution error before producing a result.
 */
@RestController
@RequestMapping("/api/v1/audit/verify")
public class AuditVerifyController {

    private final ChainVerificationService verificationService;
    private final AuditMetrics metrics;

    public AuditVerifyController(ChainVerificationService verificationService, AuditMetrics metrics) {
        this.verificationService = verificationService;
        this.metrics = metrics;
    }

    @GetMapping
    public ResponseEntity<ChainVerificationResult> verify() {
        ChainVerificationResult result;
        try {
            result = verificationService.verify();
        } catch (RuntimeException e) {
            metrics.verificationFailure(); // execution error, distinct from a "broken" result
            throw e;
        }
        metrics.verification(result.intact());
        return ResponseEntity.ok(result);
    }
}
