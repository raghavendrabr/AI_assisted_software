# Final Engineering Summary

## 1. Plan & rationale

Built a tamper-evident audit log service over an incremental, commit-by-commit process (see git
history and `docs/ai-usage-log.md`). Each commit was a self-contained slice — requirements →
scaffolding → schema → hashing → append → query/verify → security/compliance → redaction →
retention → signed export — validated end-to-end and reviewed before the next.

Core design decision: **two independent hash chains**. Base events are immutable (except a
hash-excluded redactable value); lifecycle changes (redaction, archival) are separate,
independently hash-chained *amendments*. This makes an authorized change a *positive, provable
fact* rather than something indistinguishable from tampering, and keeps lifecycle state inside
integrity protection. Full architecture: `docs/architecture.md`. Decisions: `docs/decisions/0001`–`0009`.

## 2. Artifacts

- **Runnable service** (Spring Boot 4.1 / Java 21 / PostgreSQL 16), Maven Wrapper, Docker Compose.
- **APIs:** append, filtered/paginated query, verify, redact, archive, signed export, compliance report.
- **Schema:** Flyway V1 (event chain), V2 (amendment chain), V3 (archive + manifest).
- **Hashing library:** canonical serializer + SHA-256 + Ed25519 signer + standalone bundle verifier.
- **Docs:** architecture, ADRs (0001–0013), per-scenario requirements, testing strategy, threat
  model, observability guide, reviewer-facing hardening summary, AI usage log.
- **Tests:** originally 135; **267 after the post-review hardening pass** (unit + Testcontainers
  integration; 3 POSIX-only signing-key-permission tests skipped on non-POSIX).
- **Demo:** `docs/demo.md` walkthrough + `scripts/demo.sh` end-to-end script (core chain + security
  hardening checks).

> **Post-review hardening (2026-08-19, branch `feature/security-observability-hardening`).** After
> submission, a security/auth/observability pass was added (ADRs 0010–0013): request/HTTP hardening;
> conditional dual-mode OAuth2/OIDC JWT alongside API keys; Actuator health probes + Prometheus
> domain metrics; ECS structured logging + correlation IDs. See
> `docs/security-auth-observability-improvements.md`. These were added **after** the original
> submission and are not part of the originally submitted version (see `ATTESTATION.md`).

## 3. Scenario outcomes

- **A (Greenfield):** append-only write API; query with actor/resource/eventType/time filters +
  stable cursor pagination; SHA-256 hash chain; `GET /audit/verify` detecting six+ violation types;
  validated by tampering a DB row and re-verifying.
- **B (Extension):** retention/archival (move oldest prefix + manifest + ARCHIVE amendment; verify
  reads active∪archive as one chain); salted-commitment redaction that keeps the chain intact;
  Ed25519-signed bulk export with an offline standalone verifier.
- **C (Ambiguous):** clarified the "regulators must audit access to client account data" requirement
  (`docs/requirements/scenario-c.md` + `docs/scenario-c-design.md`), implemented the access-report
  slice (success + denied client-account access, actor/account/outcome/time filters, tie-back to
  the chain), and documented the explicit scope boundary.

## 4. Risks, trade-offs & validation

| Risk / trade-off | Decision | Validation |
|---|---|---|
| Write throughput vs. one deterministic chain | Serialize on a locked head row | 25-way concurrent-append test → gap-free chain |
| False break under concurrent append during verify | REPEATABLE_READ verification | concurrent-verify test |
| Redaction privacy | Salted commitment = tamper-evidence, not confidentiality (crypto-erasure deferred) | redaction tests + documented limitation |
| Redaction/archival vs. tampering | Amendment-backed; verifier rejects unbacked changes | REDACTION_UNBACKED / ARCHIVE_PROOF_MISMATCH tests |
| Export authenticity of a filtered subset | Ed25519-signed canonical manifest; standalone verifier | tamper/reorder/remove/wrong-key rejection tests |
| Export completeness | Not proven offline (documented) | — |
| Deployed service with no signing key | Fail closed (ephemeral key only under local/test) | signer fail-closed test |

## 5. Assumptions

- Single global chain (not per-tenant); caller supplies business `eventTimestamp`, server assigns
  `recorded_at`; a single PostgreSQL instance; static API keys acceptable for the prototype;
  retention is manually triggered on a contiguous oldest prefix. Full list: `docs/assumptions.md`.

## 6. Limitations (honest)

- **Redaction** provides tamper-evidence, not confidentiality-at-rest (low-entropy values are
  brute-forceable); true erasure/crypto-erasure is future work.
- **Export** proves the bundle is unchanged, not global query completeness.
- **Retention** moves records (never destroys); hard deletion/legal erasure is out of scope.
- **Security** — the original submission used static API keys only. The **post-review pass** added a
  conditional dual-mode OAuth2/OIDC JWT resource server alongside API keys (off by default), request/
  HTTP hardening, and Actuator/metrics/structured logging (ADRs 0010–0013). **Still deferred:** mTLS,
  KMS/HSM signing, runtime API-key revocation (rotation is config + restart/reload), and gateway-tier
  rate limiting. See `docs/security-auth-observability-improvements.md` for the full boundary list.
- **Scale:** the single-chain head lock caps write throughput by design.

## 7. AI usage

AI (Claude) accelerated planning, drafting, and adversarial design review; the engineer directed
the work, reviewed every output, and corrected substantial issues (framework EOL/version, redaction
hash coverage + domain separation, export completeness claims, amendment-reference integrity,
server-side auth, concurrency ordering, fail-closed key policy, and more). Every correction is
recorded in `docs/ai-usage-log.md` with what AI proposed and what was accepted / modified /
rejected. Correctness, maintainability, and authorship remain the engineer's.

## 8. How to run & verify

See `README.md` (Getting started) and `docs/demo.md`. In short:
```
docker compose up -d                 # PostgreSQL 16
./mvnw spring-boot:run               # the service (Flyway applies V1–V3)
./mvnw test                          # 267 tests (Testcontainers; needs Docker; 3 skipped on non-POSIX)
scripts/demo.sh                      # end-to-end: append, query, verify, redact, archive, export
```
Core proof: append events, `GET /audit/verify` → intact; modify a row directly in PostgreSQL;
`GET /audit/verify` → broken with the first inconsistency and violation type.
