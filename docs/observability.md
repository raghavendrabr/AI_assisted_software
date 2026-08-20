# Observability Guide

Operational reference for the audit-log service's observability surface (implemented in Commit C —
ADR 0012). Health probes, Prometheus metrics, ECS structured logging, and correlation IDs are
**implemented**. Dashboards, alert rules, and OTLP tracing are **recommendations / design-only** and
are called out as such below — no dashboard JSON or alertmanager rules are shipped in this repo.

---

## 1. Actuator exposure matrix

Actuator runs on the **main application port** (8080). Only three endpoints are web-exposed.

| Path | Access | Notes |
|---|---|---|
| `/actuator/health/liveness` | **public** | status only |
| `/actuator/health/readiness` | **public** | status only |
| `/actuator/health` (full) | **ADMIN** | component details (`show-details: when-authorized`) |
| `/actuator/info` | **ADMIN** | |
| `/actuator/prometheus` | **ADMIN** | scrape endpoint |
| everything else (env, configprops, beans, mappings, loggers, heapdump, threaddump, shutdown, metrics, …) | **not exposed** | no handler mapped; a request fails closed at the security boundary (403); no sensitive response is served |

Authorization rules are declared before `anyRequest().denyAll()` in `SecurityConfig`, so the API
authorization is unaffected.

## 2. Liveness vs readiness

- **Liveness** (`group.liveness.include: livenessState`) reflects only whether the app process is
  alive. It has **no PostgreSQL dependency** — a transient DB outage must not cause the orchestrator
  to kill and restart an otherwise-healthy pod.
- **Readiness** (`group.readiness.include: readinessState, db`) reflects whether the app should
  receive traffic. It **includes the `db` indicator**, so the pod is not marked ready (and traffic is
  not routed) until PostgreSQL is reachable.

## 3. Metric catalog (domain)

Dotted Micrometer names; Prometheus translates to `audit_*_total`.

| Meter | Type | Tags | Meaning |
|---|---|---|---|
| `audit.events.appended` | counter | `result`=success\|failure | event append outcomes |
| `audit.append.failures` | counter | (none) | dedicated append-failure counter |
| `audit.chain.verifications` | counter | `result`=intact\|broken\|failure | verify results (failure = execution error) |
| `audit.redactions` | counter | `result`=success\|failure | redaction outcomes |
| `audit.archive.operations` | counter | `result`=success\|failure | archival outcomes |
| `audit.export.operations` | counter | `result`=success\|failure | export bundle build+sign outcomes |
| `audit.authentication.attempts` | counter | `result`, `method`, `reason` | auth attempts |

Framework metrics also present (confirmed at runtime): `http_server_requests_*`, `jvm_*`,
`hikaricp_*`, plus a common `application` tag. **Flyway metrics are not claimed** (assert only if
observed at runtime).

## 4. Tag vocabulary (exact, bounded)

Only these tag keys and values ever appear on `audit.*` meters:

- `result` ∈ { `success`, `failure`, `intact`, `broken` }
- `method` ∈ { `api_key`, `jwt`, `none`, `ambiguous` }
- `reason` ∈ { `valid-key`, `unknown-key`, `valid-token`, `invalid-token`, `both-credentials`,
  `no-credential` }
- `application` = the service name (common tag)

**Never used as a tag:** actorId, accountId, eventId, sequenceNumber, resourceId, API-key id, JWT
subject/fingerprint, requestId, exception message, or any free text. A guard test
(`AuditMetricsTest`) enforces this.

## 5. Instrumentation points

| Meter | Where incremented | Semantics |
|---|---|---|
| `audit.events.appended` / `audit.append.failures` | `AuditEventAppendService.append` | success via `TransactionSynchronization.afterCommit` (only on commit); failure on the exception path |
| `audit.chain.verifications` | `AuditVerifyController.verify` | intact/broken from the result; `failure` if verification threw |
| `audit.redactions` | `RedactionService.redactField` | success after commit; failure on exception |
| `audit.archive.operations` | `ArchiveService.archiveOlderThan` | success after commit; failure on exception |
| `audit.export.operations` | `ExportService.export` | success after bundle build+sign; failure on exception |
| `audit.authentication.attempts` | `ApiKeyAuthFilter` (key success/failure), `JwtAuthEventLoggingFilter` (JWT success), `JwtFailureMetricsEntryPoint` (JWT failure), `DualCredentialGuardFilter` (both-credentials) | one site per outcome — no double counting |

## 6. Dashboards (RECOMMENDATION — not shipped)

No dashboard files are included. A suggested Grafana layout over the Prometheus scrape:
- **Traffic & latency:** `rate(http_server_requests_seconds_count[5m])` by `uri`,`status`;
  p95 from `http_server_requests_seconds` histogram.
- **Domain throughput:** `rate(audit_events_appended_total{result="success"}[5m])`, redactions,
  archives, exports.
- **Integrity:** `audit_chain_verifications_total` split by `result` (a nonzero `broken`/`failure`
  is the headline signal).
- **Auth:** `rate(audit_authentication_attempts_total[5m])` by `result`,`method`,`reason`.
- **Resources:** `hikaricp_connections`, `hikaricp_connections_pending`, JVM heap.

## 7. Alerts (RECOMMENDATION — not deployed)

No alertmanager rules are shipped. Recommended alerts:

| Alert | Condition (PromQL sketch) | Rationale |
|---|---|---|
| Chain verification failing | `increase(audit_chain_verifications_total{result=~"broken\|failure"}[15m]) > 0` | tamper or verify error — page immediately |
| Repeated auth failures | `rate(audit_authentication_attempts_total{result="failure"}[5m]) > <threshold>` | brute-force / misconfig |
| Archive failures | `increase(audit_archive_operations_total{result="failure"}[1h]) > 0` | retention pipeline broken |
| Signing/export failures | `increase(audit_export_operations_total{result="failure"}[1h]) > 0` | signing-key or export issue |
| DB pool exhaustion | `hikaricp_connections_pending > 0 for 5m` | saturation / DB slowness |

## 8. ECS logging fields

Boot-native ECS JSON on the console (`logging.structured.format.console=ecs`; the `local` profile
uses human-readable logs). Representative fields: `@timestamp`, `log.level`, `log.logger`,
`process.thread.name`, `service.name`, `message`, `ecs.version`, and MDC entries such as
`requestId`. Example:

```json
{"@timestamp":"2026-08-20T00:15:04.421Z","log":{"level":"INFO","logger":"...AuthEventLogger"},
 "service":{"name":"audit-log-service"},
 "message":"auth method=API_KEY result=SUCCESS reason=valid-key requestId=smoke-corr-001 principal=compliance_reader-key",
 "requestId":"smoke-corr-001","ecs":{"version":"8.11"}}
```

## 9. Correlation-ID behavior

- `CorrelationIdFilter` runs first, so every response — including 400/401/403/413 — carries an
  `X-Request-Id` header and the same value in the `requestId` MDC field (hence in ECS logs).
- Inbound `X-Request-Id` is honored only if it matches `[A-Za-z0-9._-]{1,64}`; otherwise a UUID is
  generated. Invalid/oversized values are never logged or echoed.
- The value is cleared from MDC in a `finally` block (no cross-request leakage); the filter runs on
  the initial request dispatch only (no async/error re-dispatch duplication).
- The W3C `traceparent` header is **never** used as the request id (tracing is design-only).

## 10. Sensitive-data rules

Never logged and never used as a metric tag: API keys and their SHA-256 digests; JWTs, signatures,
or claims maps; plaintext payload values; redactable values; salts/commitments; signing-key bytes.
JWT identity is logged only as a stable fingerprint (`jwt:<16 hex>`), never the raw subject. Auth log
fields are sanitized (control chars incl. CR/LF stripped, length-bounded) to prevent log injection.
Guard tests: `AuthLoggingNoSecretsIntegrationTest`, `StructuredLoggingSafetyTest`, `AuditMetricsTest`.

## 11. OTLP tracing (DESIGN-ONLY — not implemented)

No `micrometer-tracing`/OpenTelemetry/OTLP dependency is present and `traceparent` is not propagated.
When added, the correlation filter would coexist with trace/span ids (the requestId remains a
first-class field). This is intentionally deferred.

## 12. Operational troubleshooting examples

- **"Is the service healthy?"** — `curl localhost:8080/actuator/health/liveness` (public) →
  `{"status":"UP"}`. For DB status, `curl -H "X-API-Key: <admin>" localhost:8080/actuator/health`
  (ADMIN) shows the `db` component.
- **"Correlate a client error to logs."** — the client's response carries `X-Request-Id`; grep the
  ECS logs for that `requestId`.
- **"Is the chain intact right now?"** — scrape
  `audit_chain_verifications_total{result="broken"}` / `{result="failure"}`; both should be 0. (A
  verify run is what advances these — call `GET /api/v1/audit/verify` as COMPLIANCE_READER/ADMIN.)
- **"Are we seeing auth abuse?"** — `audit_authentication_attempts_total{result="failure"}` by
  `reason`.
- **"DB saturation?"** — `hikaricp_connections_pending` and `hikaricp_connections`.
