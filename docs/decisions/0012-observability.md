# ADR 0012 — Observability: Actuator, Prometheus Metrics, Structured Logging & Correlation IDs

- **Status:** Accepted
- **Date:** 2026-08-19
- **Context:** Commit C adds an operational-observability foundation: health probes, a Prometheus
  scrape endpoint, domain metrics, Boot-native structured (ECS JSON) logging, and request
  correlation ids. Distributed tracing (OpenTelemetry/OTLP) and alerting rules are **design-only**
  here (recorded at the end), not implemented.

## Dependencies
- `spring-boot-starter-actuator` and `io.micrometer:micrometer-registry-prometheus` — both
  BOM-managed by Spring Boot 4.1 (micrometer 1.17.0). **No** `logstash-logback-encoder` and **no**
  OpenTelemetry/OTLP dependencies. **No** custom `logback-spring.xml` — Boot-native structured
  logging suffices.

## Actuator exposure & authorization
- Endpoints stay on the **main application port** (8080).
- **Exposure allow-list:** only `health`, `info`, and `prometheus` are web-exposed
  (`management.endpoints.web.exposure.include`, declared as a YAML list). Everything else — `env`,
  `configprops`, `beans`, `mappings`, `loggers`, `heapdump`, `threaddump`, `shutdown`, `metrics`,
  … — is therefore **not exposed**.
- **Authorization** (`SecurityConfig`, rules declared before `anyRequest().denyAll()`):
  - `/actuator/health/liveness` and `/actuator/health/readiness` → **public** (for k8s /
    load-balancer probes);
  - `/actuator/health/**`, `/actuator/info`, `/actuator/prometheus` → **ADMIN**;
  - **Dangerous/other actuator endpoints** (env, configprops, beans, mappings, loggers, heapdump,
    threaddump, shutdown, metrics, …) are **not included in web exposure**, so no handler is mapped
    for them. A request to such a path currently **fails closed at the security boundary with 403**
    (the fail-closed authorization chain denies it) rather than reaching a handler — so **no
    endpoint handler runs and no sensitive endpoint response is ever served**. (Whether the boundary
    answers 403 vs a 404 for an unmapped path is immaterial to the security property: the endpoint
    is neither exposed nor served.)
- **Health-detail hiding:** `show-details`/`show-components: when-authorized`, so an unauthenticated
  probe sees **status only**; an ADMIN sees full component details.
- **Health groups:** `liveness = livenessState` (NO PostgreSQL dependency — a transient DB blip must
  not kill the pod), `readiness = readinessState, db` (not ready until PostgreSQL is reachable, so
  traffic isn't routed before the DB is up).

## Structured logging
- **Boot-native ECS JSON** on the console: `logging.structured.format.console=ecs`. MDC values
  (notably `requestId`) are included in the ECS output automatically.
- The **`local` profile disables** structured logging (empty `console` format) so developers get
  human-readable console logs.
- **No secret material is logged** anywhere — building on the sanitized `AuthEventLogger` (ADR 0011),
  the service does not log API keys or digests, JWTs/signatures/claims, plaintext payload values,
  redactable values, salts/commitments, or signing-key bytes. A logging-safety test captures ECS
  output during real traffic and asserts these are absent and that each line is valid JSON.

## Correlation IDs
- `CorrelationIdFilter` runs **first** in the security chain (before body-size, dual-credential,
  API-key, and JWT filters), so 400 / 401 / 403 / 413 responses also carry a request id.
- Inbound `X-Request-Id` is accepted **only** if it matches a bounded safe pattern
  (`[A-Za-z0-9._-]{1,64}`); otherwise a UUID is generated. Invalid/oversized values are never logged
  or echoed — they are simply replaced. The W3C `traceparent` header is **never** treated as the
  request id (tracing is deferred).
- The id is put in MDC and **removed in a `finally`** block, so it never leaks to a later request on
  the same thread. The filter runs on the initial REQUEST dispatch only (`shouldNotFilterAsync/Error`
  return true), so MDC is set once and cleared once — no duplication across async/error re-dispatch.
- Filters that call `response.reset()` before writing an early error (413 body-size, 400
  both-credentials) **re-apply** the id via `CorrelationIdFilter.reapplyRequestId(...)`, so the
  header survives on those responses.

## Metrics
- `AuditMetrics` wraps Micrometer's `MeterRegistry` with **dotted meter names** (Prometheus
  translates to `audit_*_total`) and **bounded tags only**.

| Meter (dotted) | Tags | Incremented at |
|---|---|---|
| `audit.events.appended` | `result`=success\|failure | `AuditEventAppendService.append` — **success after commit** (TransactionSynchronization `afterCommit`), failure on the exception path |
| `audit.append.failures` | (none) | same — dedicated failure counter |
| `audit.chain.verifications` | `result`=intact\|broken\|failure | `AuditVerifyController.verify` — intact/broken from the result, `failure` if verification threw |
| `audit.redactions` | `result`=success\|failure | `RedactionService.redactField` — **success after commit**, failure on exception |
| `audit.archive.operations` | `result`=success\|failure | `ArchiveService.archiveOlderThan` — **success after commit**, failure on exception |
| `audit.export.operations` | `result`=success\|failure | `ExportService.export` — success after bundle build+sign, failure on exception |
| `audit.authentication.attempts` | `result`, `method`=api_key\|jwt\|none\|ambiguous, `reason` (fixed enum) | one site per outcome: API-key success/failure in `ApiKeyAuthFilter`; JWT success in `JwtAuthEventLoggingFilter`; JWT failure in `JwtFailureMetricsEntryPoint`; both-credentials in `DualCredentialGuardFilter` |

- **Transactional success semantics:** append/redaction/archive success counters fire only in
  `afterCommit`, so a rollback never counts a success. Failures are counted immediately (in-memory
  counters are unaffected by DB rollback).
- **No double counting:** each authentication outcome is recorded at exactly one site (documented
  above). The JWT-failure entry point delegates to the standard `BearerTokenAuthenticationEntryPoint`
  so the RFC 6750 `WWW-Authenticate: Bearer` challenge from ADR 0011 is preserved.
- **Tag discipline:** tags are drawn only from fixed enums (`result`, `method`, `reason`). No
  identifier or free text is ever a tag — never actorId, accountId, eventId, sequenceNumber,
  resourceId, API-key id, JWT subject/fingerprint, requestId, or an exception message. A guard test
  asserts the audit_* series carry only the bounded tag keys.
- **Confirmed runtime series** in `/actuator/prometheus` (asserted by test): the domain
  `audit_*_total`, `http_server_requests`, `jvm_memory_used_bytes`, and `hikaricp_connections`.
  **Flyway metrics are NOT claimed** — they are asserted only if observed, and the test does not
  assert them.

## Deferred (design-only, NOT implemented in this commit)
- **Distributed tracing (OpenTelemetry/OTLP):** no `micrometer-tracing`/OTLP dependency is added and
  `traceparent` is not propagated. When added, the correlation filter would coexist with trace/span
  ids rather than be replaced.
- **Alerting rules:** the intended alerts — chain-verification failure (`audit_chain_verifications_total{result="broken"|"failure"} > 0`),
  repeated authentication failures, archive failure, signing failure, and DB connection-pool
  exhaustion (`hikaricp_connections_pending`) — are documented as the operational follow-up but no
  alert manager rules are shipped here.

## Consequences
- Additive and backward compatible: no API contract changes; existing auth and endpoints are
  unchanged. New surface is the three actuator endpoints (probes public, rest ADMIN), the
  `X-Request-Id` response header, ECS console logs by default (human-readable under `local`), and the
  domain metrics.

## Test configuration model (main + test profile)
Tests do **not** shadow the main configuration. The suite loads
`src/main/resources/application.yml` first and then applies **overrides only** from
`src/test/resources/application-test.yml`, because the `test` profile is active. Profile activation
is centralized:
- the shared `@AbstractPostgresIntegrationTest.WithPostgres` meta-annotation carries
  `@ActiveProfiles("test")`, so every integration test using it activates the profile without
  repeating the annotation;
- the two non-Postgres `@SpringBootTest` classes declare `@ActiveProfiles("test")` directly.

`application-test.yml` contains only test-specific values (non-production API keys; a deliberate
`audit.limits.max-request-bytes` override used to prove layering). The `test` profile also enables
the Ed25519 ephemeral-key fallback (fail-closed policy). Observability config (actuator exposure,
health groups, ECS logging) is **not** redefined for tests — it comes from the main configuration,
so tests exercise the real setup. `ConfigurationLoadingTest` proves this: a main-only property
remains loaded, the test override wins, and actuator exposure/health come from main.

## Validation
`./mvnw clean verify` green. Tests: actuator exposure/authorization (probes public; full
health/info/prometheus 401→403→200 by role; ADMIN JWT 200; dangerous endpoints not served; API
denyAll intact); correlation (valid echoed, missing/invalid/oversized replaced, present on
200/401/403/413, MDC cleared, no cross-thread leak, requestId in ECS log); metrics (append success
only after commit; rolled-back append counts failure not success; intact/broken verification;
redaction/archive/export success/failure; auth success/failure once; bounded tags; Prometheus
contains domain+HTTP+JVM+Hikari); logging safety (valid ECS JSON, requestId present, no secrets).

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-19.
