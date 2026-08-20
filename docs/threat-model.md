# Threat Model

Scope: the tamper-evidence and access-control guarantees of the audit log service. The central
adversary is someone with **direct data-store access** (the assignment's core validation) plus
API-level attackers.

## Assets

- The integrity of the append-only event history (no undetectable modification/deletion).
- The provability of authorized lifecycle changes (redaction, archival).
- The confidentiality of the export-signing private key and the API keys.

## Adversaries & mitigations

| Adversary / attack | Mitigation | Detection |
|---|---|---|
| **Direct DB tamper** — modify a stored event field or payload | `content_hash` covers all integrity fields; verifier recomputes it | `CONTENT_HASH_MISMATCH` |
| **Direct DB tamper** — change a record's `previous_hash` / reorder | chain linkage checked in walk order | `PREVIOUS_HASH_MISMATCH` |
| **Direct DB tamper** — delete a record | strict sequence walk (active∪archive) | `SEQUENCE_GAP` |
| **Direct DB tamper** — corrupt a stored hash length | DB CHECK + verifier length check | `MALFORMED_STORED_HASH` |
| **Direct DB tamper** — desync the chain-head row | head compared to recomputed tip | `CHAIN_HEAD_MISMATCH` |
| **Silent redaction** — null a redactable value without authorization | null value requires a backing REDACTION amendment | `REDACTION_UNBACKED` |
| **Value/salt tamper** on a redactable field | value re-checked against its commitment | `COMMITMENT_MISMATCH` |
| **Amendment tamper/reorder/delete** | amendment chain recomputed + linked | `AMENDMENT_CHAIN_BROKEN` |
| **Archive tamper** — modify/delete/duplicate archived record or swap manifest | merged-stream walk + manifest binding | `ARCHIVE_PROOF_MISMATCH` / `SEQUENCE_GAP` |
| **Forged commitment replay** across event/field | commitment domain-separated + bound to eventId+field | recompute fails |
| **Export tamper** — modify/reorder/remove/insert records or amendments | Ed25519 signature over a canonical manifest; standalone recompute | signature/hardcheck fail |
| **Export forgery** — fabricate a bundle | requires the private signing key (never the API key; never committed) | signature fails |
| **Unauthorized API access** | `X-API-Key` → server-side role; fail-closed `denyAll()` | 401 / 403 |
| **Client-supplied role escalation** | role never accepted from the client; resolved server-side | — |
| **Weak/duplicate key config** | fail-fast on duplicate/multi-role keys; whitespace treated as unset | startup abort |
| **Deployed with no signing key** | ephemeral key only under local/test; else fail closed | startup abort |
| **Oversized request body** (memory/CPU exhaustion) | streaming byte cap on write endpoints (`audit.limits.max-request-bytes`, default 64 KiB), incl. chunked/unknown-length | 413 |
| **Deeply-nested / huge-token JSON** (parser exhaustion) | Jackson `StreamReadConstraints` (depth 32, string 64 KiB, number 128) on the request mapper, before a `JsonNode` is built | safe 400 |
| **Unbounded redactable-field set** | Bean Validation bounds count (≤64) + per-path length (≤128) + identifier syntax | 400 |
| **Endpoint discovery via public API docs** | OpenAPI/Swagger off by default; when on, public only if explicitly configured, else ADMIN-only (`audit.docs.*`) | 401/403 |
| **Spoofed forwarding headers** (fake client IP/scheme) | `X-Forwarded-*` NOT trusted by default (`forward-headers-strategy: none`); trusted only under the `proxy` profile behind a proxy that overwrites inbound headers | ignored by default |
| **World-readable signing-key file** | POSIX perm check on the private key: fail-closed outside local/test, warn under local/test; non-POSIX relies on platform ACLs | startup abort (deployed) |
| **Forged / tampered JWT** (when JWT enabled) | signature verified against issuer JWKS; explicit algorithm allow-list; issuer + audience + exp + nbf validated | 401 |
| **Client self-assigns a role via token claims** | only trusted `scope`/`scp` scopes map to roles; `roles`/`authorities`/`groups` claims ignored; no default role | 403 |
| **Ambiguous dual credentials** (Bearer + X-API-Key) | rejected before either mechanism runs | 400 |
| **Invalid Bearer downgraded to API key** | API-key filter never runs when a Bearer header is present and never overwrites a JWT auth — no fallback | 401 |
| **Half-configured JWT silently accepting tokens** | enabled-but-incomplete config is a fatal startup error | startup abort |
| **Log injection via untrusted claim/key text** | all logged auth fields sanitized (control chars incl. CR/LF stripped, length bounded); credentials/tokens/digests never logged | — |
| **Actuator information disclosure** | allow-list exposes only health/info/prometheus; env/beans/configprops/heapdump/threaddump/loggers/shutdown NOT exposed; health details hidden from unauthenticated callers; full health/info/prometheus require ADMIN | 401/403/404 |
| **Sensitive data in metrics/logs** | metric tags are bounded enums only (no ids/subjects/messages); ECS logs never contain keys/tokens/payloads/redactable values/salts/signing-key bytes | guard tests |
| **Correlation-id spoofing / log forging** | inbound X-Request-Id accepted only if it matches `[A-Za-z0-9._-]{1,64}`, else a UUID is generated; invalid values never logged; MDC cleared in finally | — |

## Residual risks / assumptions

- **Attacker who can rewrite the ENTIRE chain consistently** (recompute every hash + head) inside
  the DB is not detectable by the verifier alone — this is inherent to a self-contained hash chain.
  Mitigation in production: periodically **publish the chain-head hash** to an external, tamper-
  resistant location (notary/transparency log) so a wholesale rewrite is detectable. Out of scope
  for the prototype; noted as future work.
- **Redaction confidentiality:** salt + commitment allow offline brute-force of low-entropy values.
  Tamper-evidence, not confidentiality-at-rest (ADR 0007).
- **Export completeness:** a signed bundle is not proof that no other matching records exist.
- **Key management:** file/ephemeral keys are prototype-grade; production needs a KMS/secret manager,
  key rotation, and trusted public-key distribution (a `signingKeyId` is a hint, not trust — ADR 0009).
- **Authentication:** API keys remain supported; an optional OAuth2/OIDC **JWT resource-server mode**
  is now available (dual-mode, off by default — ADR 0011). Two honest limitations: (a) **key
  rotation/revocation for API keys is configuration + restart/reload** — there is no runtime
  revocation API; (b) when JWT is enabled, the **issuer/JWKS must be reachable** — if it is not,
  token validation fails closed (401), never open. mTLS is still out of scope.
- **Transport security:** TLS/mTLS is assumed to be terminated by the deployment environment; not
  configured in the prototype. HSTS is emitted only over HTTPS, so it is inert on plain-HTTP local
  runs and takes effect once TLS is terminated in front of (or at) the service.
- **Response headers:** Spring Security defaults (`X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Cache-Control`) are retained; `Referrer-Policy: no-referrer` and a
  restrictive `Permissions-Policy` are added. No Content-Security-Policy is set — this is a JSON
  API with no first-party browser UI, and a CSP would only be added after live verification against
  the (optional) Swagger UI.
- **CORS:** disabled by explicit decision — no browser front-end consumes this API, so no
  cross-origin access is granted (recorded, not omitted).
- **Rate limiting / brute-force throttling:** still **not implemented**. This is acknowledged as a
  production requirement, deferred with rationale: it belongs at the API gateway / reverse proxy
  tier (or a shared store for multi-instance correctness), not in the single-instance prototype.
  Constant-time API-key comparison already removes a timing side-channel, but request-rate abuse is
  unmitigated in-process. Tracked as future work.
- **Database-privilege blast radius:** the application connects as the schema **owner**, so a
  compromised app credential could `UPDATE`/`DELETE` integrity columns directly (detectable only by
  later chain re-verification). No DB-level immutability (triggers/REVOKE) is enforced. A
  **least-privilege runtime role + DB-level immutability** model is designed in **ADR 0013** but is
  **design-only / not implemented** — the tamper-evidence guarantee still holds via the hash chain;
  this would add defense-in-depth. (An attacker with the `audit_owner`/DB-superuser credential and
  the ability to rewrite the entire chain remains covered only by external notarization, above.)
- **Observability endpoints:** metrics/health are ADMIN-gated except the status-only liveness/
  readiness probes; no sensitive data is exposed in metrics, logs, or health details.
- **Alerting & CI:** recommended alert rules (chain-verify failure, auth-failure spikes, archive/
  signing failure, DB pool exhaustion) are documented in `docs/observability.md` but **not deployed**;
  no automated CI/dependency-scanning pipeline is configured yet. Both are future work.
