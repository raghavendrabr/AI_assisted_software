package com.raghavendra.audit.verify;

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
 */
@RestController
@RequestMapping("/api/v1/audit/verify")
public class AuditVerifyController {

    private final ChainVerificationService verificationService;

    public AuditVerifyController(ChainVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @GetMapping
    public ResponseEntity<ChainVerificationResult> verify() {
        return ResponseEntity.ok(verificationService.verify());
    }
}
