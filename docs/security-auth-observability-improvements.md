# Security, Authentication & Observability — Reviewer-Facing Improvement Summary

This document summarizes the post-review hardening pass applied to the audit-log service after the
original submission. It maps each reviewer concern to: **previous behavior → improvement implemented
→ security/operational benefit → tests proving it → remaining production boundary**.

The work landed in four focused commits on `feature/security-observability-hardening`:
- **A** — request & HTTP hardening (ADR 0010)
- **B** — conditional dual-mode JWT + API-key auditability (ADR 0011)
- **C** — actuator, Prometheus metrics, structured logging, correlation IDs (ADR 0012)
- **D** — this documentation, threat-model, and reviewer summary

> **Scope note.** These improvements were added **after** the original submission (dates in
> `ATTESTATION.md` are unchanged). They did **not** exist in the originally submitted version.

Full suite after the pass: **267 tests, 0 failures, 3 skipped** (the 3 skips are POSIX-only
signing-key-permission tests — see the last row).

---

## 1. Request body / JSON parse limits

- **Reviewer identified:** no bound on request-body size or JSON structure → memory/CPU exhaustion.
- **Previous behavior:** unbounded body; `payload` `JsonNode` and `redactableFields` unvalidated.
- **Improvement:** a streaming `RequestBodySizeLimitFilter` caps the body
  (`audit.limits.max-request-bytes`, default 64 KiB) — early `Content-Length` check plus a
  byte-counting stream for chunked/unknown-length bodies, never caching the body → **413**. Jackson
  `StreamReadConstraints` (depth 32, string 64 KiB, number 128) reject pathological JSON → **safe
  400** with no payload echoed. `redactableFields` bounded in count (≤64), path length (≤128), and
  identifier syntax.
- **Benefit:** bounded resource use before an event is parsed/persisted; no oversized/deeply-nested
  DoS vector.
- **Tests:** `RequestBodyLimitIntegrationTest` (413 on Content-Length and chunked, at-limit success,
  no echo), `JsonConstraintsIntegrationTest` (depth/string/number → 400, no echo),
  `RedactableFieldValidationTest`.
- **Boundary:** limits are static config; no per-client quota (rate limiting is gateway-tier — §12).

## 2. Swagger / OpenAPI gating

- **Reviewer identified:** OpenAPI/Swagger publicly reachable (endpoint disclosure).
- **Previous behavior:** `/v3/api-docs` and `/swagger-ui` were `permitAll()`.
- **Improvement:** gated by `audit.docs.*` — **off and non-public by default**; the `local` profile
  makes them public for dev; when enabled-but-not-public they require **ADMIN**. Wired to both
  springdoc enablement and the security matrix (a single property, not competing chains).
- **Benefit:** the API surface is not enumerable by anonymous callers in a deployed profile.
- **Tests:** `SwaggerDisabledByDefaultTest`, `SwaggerLocalPublicTest`,
  `SwaggerEnabledPrivateAdminOnlyTest`.
- **Boundary:** none material; this is defense-in-depth.

## 3. Security & error response headers

- **Reviewer identified:** no explicit security-header policy; error responses could leak internals.
- **Previous behavior:** relied on defaults; error verbosity not pinned.
- **Improvement:** retained Spring Security defaults (`X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Cache-Control`); added `Referrer-Policy: no-referrer` and a restrictive
  `Permissions-Policy`; **HSTS only over HTTPS**; **no CSP** (JSON API, no first-party browser UI).
  Pinned `server.error.include-message/-stacktrace/-binding-errors = never`.
- **Benefit:** consistent hardened headers; error bodies never expose messages/stack traces.
- **Tests:** `SecurityHeadersIntegrationTest` (headers present; HSTS absent over HTTP).
- **Boundary:** TLS termination is assumed upstream (HSTS is inert until then).

## 4. Reverse-proxy trust model

- **Reviewer identified:** forwarded headers must not be trusted blindly.
- **Previous behavior:** not addressed.
- **Improvement:** `server.forward-headers-strategy: none` by default; a separate **`proxy`** profile
  (`application-proxy.yml`) enables `framework`, documenting that the trusted proxy must overwrite
  inbound `X-Forwarded-*` and that direct app access must be network-restricted.
- **Benefit:** a client cannot spoof its address/scheme unless a correctly-configured proxy is in
  front.
- **Tests:** `SecurityHeadersIntegrationTest.forwardedHeaders_notTrusted_inDefaultProfile`.
- **Boundary:** the proxy profile documents preconditions; enforcing them is a deployment concern.

## 5. Ed25519 signing-key file permissions

- **Reviewer identified:** a world-readable private key should be rejected.
- **Previous behavior:** the PEM was read without checking permissions.
- **Improvement:** a **pure, platform-independent** `SigningKeyPermissionPolicy` classifies the
  permission set; `Ed25519Signer` reads POSIX permissions and, on a group/other-accessible key,
  **fails closed outside local/test** and warns under local/test. Non-POSIX filesystems (Windows)
  are handled explicitly (documented reliance on platform ACLs).
- **Benefit:** a deployed service refuses to start with an over-permissive signing key.
- **Tests:** `SigningKeyPermissionPolicyTest` (all cases, every OS) +
  `Ed25519KeyPermissionTest` (filesystem-level, POSIX-only).
- **Boundary:** KMS/HSM-backed keys remain design-only (ADR 0009).

## 6. Conditional JWT + API-key dual mode

- **Reviewer identified:** static API keys are prototype-grade; a production auth story was needed.
- **Previous behavior:** API keys only.
- **Improvement:** an **optional** OAuth2/OIDC JWT resource server (`audit.security.jwt.*`, **off by
  default**) runs alongside API keys. It is wired **only when enabled AND complete**; enabled-but-
  incomplete config **fails startup** (never silently accepts tokens). Bound to a dedicated namespace
  so Boot's auto-config isn't triggered when disabled. When disabled, a `Bearer` token is an
  unrecognized credential → 401.
- **Benefit:** a credible production auth path with a safe default and fail-closed activation.
- **Tests:** `JwtAuthenticationIntegrationTest`, `JwtDisabledIntegrationTest`,
  `JwtConfigStartupTest` — using a **real `NimbusJwtDecoder`** with locally-generated keys served
  from an in-test JWKS endpoint (no live IdP).
- **Boundary:** no live IdP is bundled; production supplies issuer/JWKS.

## 7. JWT validation (issuer/audience/signature/algorithm/exp/nbf)

- **Reviewer identified:** tokens must be fully validated.
- **Improvement:** the decoder validates **cryptographic signature**, an explicit **algorithm
  allow-list** (RS256/ES256), **issuer**, **audience**, and **expiration + not-before**. Structurally
  invalid tokens fail in decoding.
- **Benefit:** forged, expired, not-yet-valid, wrong-issuer/audience, or wrong-algorithm tokens are
  rejected with 401 + RFC 6750 `WWW-Authenticate: Bearer`.
- **Tests:** `JwtAuthenticationIntegrationTest` + `AuthResponseProtocolIntegrationTest` (expired,
  not-before, malformed, wrong-signature, disallowed-algorithm, wrong-issuer, wrong-audience).
- **Boundary:** clock-skew tolerance uses the framework default.

## 8. Scope-to-role authorization

- **Reviewer identified:** never trust client-declared roles; least privilege.
- **Improvement:** only trusted scopes map to roles — `audit.write → WRITER`, `audit.read →
  COMPLIANCE_READER`, `audit.admin → ADMIN`. Client `roles`/`authorities`/`groups` claims are
  **ignored**; there is **no default role** (no mapped scope → 403). Both auth mechanisms feed the
  same authorization matrix and `denyAll()`.
- **Benefit:** a client cannot self-assign a role; access is least-privilege by construction.
- **Tests:** `JwtScopeRoleConverterTest`, and 403 cases in `JwtAuthenticationIntegrationTest`
  (missing/insufficient scope, roles-claim-only, unknown scopes).
- **Boundary:** scope→role mapping is configurable but validated at startup.

## 9. Ambiguous-credential rejection

- **Reviewer identified:** supplying two credentials is ambiguous.
- **Improvement:** `DualCredentialGuardFilter` rejects a request carrying **both** `Bearer` and
  `X-API-Key` with a safe **400** (structured `ApiError`, `application/json`, no credential echoed),
  before either mechanism runs. An invalid Bearer **never** falls back to an API key; the API-key
  filter never overwrites a JWT authentication.
- **Benefit:** no silent downgrade or credential-confusion attack surface.
- **Tests:** `AuthResponseProtocolIntegrationTest.bothCredentials_400_...`,
  `JwtAuthenticationIntegrationTest.invalidBearer_doesNotFallBackToApiKey`.
- **Boundary:** none.

## 10. API-key IDs & honest rotation limitations

- **Reviewer identified:** keys need identifiers and an honest rotation story.
- **Improvement:** each key has a stable, **non-secret** id (`audit.security.api-keys[].id`),
  validated at startup for safe characters, bounded length, and uniqueness; used only in sanitized
  logs (never the key or its digest).
- **Benefit:** operators can reference/audit a key without exposing it.
- **Tests:** `ApiKeyIdAuditabilityTest`.
- **Boundary (honest):** **rotation/revocation requires a configuration update and an application
  restart/reload** — there is **no runtime revocation API** in this prototype.

## 11. Actuator exposure

- **Reviewer identified:** no operational endpoints, and any added must be safe.
- **Previous behavior:** no actuator.
- **Improvement:** actuator on the **main port**, allow-listing only `health`, `info`, `prometheus`.
  Dangerous endpoints (env, configprops, beans, mappings, loggers, heapdump, threaddump, shutdown,
  metrics) are **not exposed** — no handler is mapped; a request fails closed at the security boundary
  (403) so **no sensitive endpoint response is ever served**. Health details are hidden from
  unauthenticated callers.
- **Benefit:** operational visibility without information disclosure.
- **Tests:** `ActuatorSecurityIntegrationTest`, `ActuatorJwtAdminIntegrationTest`.
- **Boundary:** none material.

## 12. Liveness / readiness semantics

- **Improvement:** `/actuator/health/liveness` and `/readiness` are **public** (status only).
  **Liveness = livenessState** (no DB dependency — a transient DB blip must not kill the pod);
  **readiness = readinessState + db** (not ready until PostgreSQL is reachable). Full health requires
  ADMIN.
- **Benefit:** correct k8s/load-balancer probe semantics.
- **Tests:** `ActuatorSecurityIntegrationTest` (probes public + status-only), `ConfigurationLoadingTest`
  (readiness includes db).

## 13. Prometheus / domain metrics

- **Improvement:** Micrometer → Prometheus with **dotted meter names** and **bounded enum tags
  only**. Families: `audit.events.appended`, `audit.append.failures`, `audit.chain.verifications`,
  `audit.redactions`, `audit.archive.operations`, `audit.export.operations`,
  `audit.authentication.attempts`. Append/redaction/archive successes are counted **after commit**;
  each auth outcome is recorded at exactly one site.
- **Benefit:** actionable operational + domain signals without high-cardinality or sensitive labels.
- **Tests:** `AuditMetricsTest`, `MetricsIntegrationTest` (commit-safe counting; Prometheus contains
  domain + HTTP + JVM + Hikari series; bounded tags).
- **Boundary:** Flyway metrics are not claimed; alerting rules are documented, not deployed (§16).

## 14. Structured (ECS) logging

- **Improvement:** Boot-native ECS JSON (`logging.structured.format.console=ecs`); the `local`
  profile keeps human-readable logs. No `logstash-logback-encoder`, no custom `logback-spring.xml`.
- **Benefit:** machine-parseable logs for aggregation, with `requestId` correlation.
- **Tests:** `StructuredLoggingSafetyTest` (valid ECS JSON, `requestId` present).

## 15. Sanitized correlation IDs

- **Improvement:** `CorrelationIdFilter` runs first, so 400/401/403/413 responses carry a request id.
  Inbound `X-Request-Id` is accepted only if it matches `[A-Za-z0-9._-]{1,64}`, else a UUID is
  generated; invalid values are never logged. `requestId` goes to MDC (in ECS logs) and the response
  header, and is cleared in `finally`. `traceparent` is never used as the request id.
- **Benefit:** end-to-end request correlation without log-injection or cross-request leakage.
- **Tests:** `CorrelationIdFilterTest` (incl. concurrency/no-leak), `CorrelationIdIntegrationTest`
  (echoed/replaced; present on 401/403/413; MDC cleared).

## 16. Secret / PII avoidance

- **Improvement:** across all of the above, **no secret material is logged or tagged** — never API
  keys or their SHA-256 digests, JWTs/signatures/claims maps, plaintext payload values, redactable
  values, salts/commitments, or signing-key bytes. A JWT identity is logged only as a stable
  fingerprint (`jwt:<16 hex>`), never the raw subject. Metric tags are bounded enums only.
- **Benefit:** logs and metrics are safe to aggregate and retain.
- **Tests:** `AuthLoggingNoSecretsIntegrationTest`, `StructuredLoggingSafetyTest`,
  `AuditMetricsTest` (bounded-tag guard), `AuthEventLoggerTest` (sanitizer + fingerprint).

---

## Remaining production boundaries (honest)

- **API-key rotation/revocation** — configuration update + restart/reload; no runtime revocation API.
- **No live IdP bundled** — JWT tests use locally-generated keys + an in-test JWKS.
- **Rate limiting** — deferred to the gateway/proxy tier; not implemented in-process.
- **OpenTelemetry / OTLP tracing** — design-only; not implemented (`traceparent` not propagated).
- **Alert definitions** — documented (`docs/observability.md`) but not deployed (no alertmanager
  rules or dashboards shipped).
- **DB least-privilege & DB-level immutability** — design-only (ADR 0013); the prototype connects as
  the schema owner.
- **KMS/HSM signing, mTLS, crypto-erasure redaction, Merkle export-completeness, external
  notarization** — remain deferred (ADRs 0009, 0007; threat-model).
- **CI / dependency scanning** — none is currently configured; documented as a future improvement.
- **POSIX signing-key-permission tests** — the filesystem-level cases run when the suite executes on
  a **POSIX filesystem**; they are skipped on non-POSIX (e.g. Windows/NTFS) via a JUnit assumption.
  The permission *decision* is covered on every OS by pure-function unit tests. CI is not currently
  configured (future improvement), so these run today when the suite is executed on POSIX.
