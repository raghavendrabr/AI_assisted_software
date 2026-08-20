# ADR 0010 — Request & Security Hardening

- **Status:** Accepted
- **Date:** 2026-08-19
- **Context:** A reviewer-facing production-readiness pass. The cryptographic core (hash chains,
  fail-closed authz, constant-time key comparison, fail-closed signing key) was already solid; the
  gaps were operational request-handling and HTTP hardening. This ADR records the request/security
  hardening slice (Commit A). Authentication (OAuth2/JWT) and observability are separate commits and
  are **not** covered here.

## Decisions

### 1. Request-body size cap (streaming, fail-safe on unknown length)
A `RequestBodySizeLimitFilter` enforces `audit.limits.max-request-bytes` (default **64 KiB**) on
write endpoints (`POST`/`PUT`/`PATCH` under `/api/v1/`). It rejects two ways without ever caching
the whole body:
- an early check when a `Content-Length` is present and over the limit → **413** immediately;
- a **streaming byte counter** wrapped around the request `ServletInputStream` that trips at the
  limit while the controller reads the body → **413**. This catches **chunked / unknown-length**
  bodies (and a `Content-Length` that under-reports the real size), which the servlet-container form
  limits (`server.tomcat.max-http-form-post-size`) do **not** cover for arbitrary JSON.

The 413 body is static and never echoes any received bytes.

### 2. Jackson stream constraints (before `JsonNode` construction)
`StreamReadConstraints` is applied to the MVC request mapper via a Boot
`JsonFactoryBuilderCustomizer` bean (not a replacement `ObjectMapper`, so all other Boot Jackson
configuration is preserved): **max nesting depth 32, max string length 65,536, max number length
128**. Violations fail during parsing and surface as a **safe 400** with no payload fragment
echoed. This bounds parser CPU/memory before an event is materialized.

### 3. Bounded `redactableFields`
Bean Validation caps the list at **64** entries, each **≤128** characters and matching
`[A-Za-z0-9_.-]+` (a single top-level identifier — all the redaction model supports). Prevents an
unbounded or malformed set of redactable paths.

### 4. OpenAPI/Swagger exposure (`audit.docs.*`)
Docs are **fail-closed** by default: `audit.docs.enabled=false`, `audit.docs.public=false`, and
springdoc enablement tracks `audit.docs.enabled`. Behavior:
- `enabled=true, public=true` → docs are public (the **`local`** profile turns this on for dev);
- `enabled=true, public=false` → docs require **ADMIN**;
- `enabled=false` → docs are not served and the paths fall through to `denyAll()`.

This is a single `SecurityFilterChain` consulting a property — **not** competing filter-chain beans.
(Reclassified from P0 to **P1 defense-in-depth**: it was endpoint disclosure, not a direct
vulnerability.)

### 5. Error responses pinned closed
`server.error.include-message`, `include-stacktrace`, and `include-binding-errors` are pinned to
`never`. These are already the Boot defaults; pinning prevents a future default change from silently
leaking internals.

### 6. Response security headers
Spring Security defaults (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Cache-Control`) are retained. Added: `Referrer-Policy: no-referrer` and a restrictive
`Permissions-Policy`. **HSTS applies only over HTTPS** (Security's default), so it is inert on
plain-HTTP local runs. **No CSP** is added — this is a JSON API with no first-party browser UI, and
a CSP would only be introduced after live verification against the optional Swagger UI.

### 7. CORS disabled (explicit)
No browser front-end consumes this API, so cross-origin browser access is denied by an explicit
decision (`cors.disable()`), recorded rather than left implicit.

### 8. Forwarded headers not trusted by default
Base config sets `server.forward-headers-strategy: none`. A separate **`proxy`** profile
(`application-proxy.yml`) sets it to `framework`. That profile documents the preconditions:
- the trusted proxy MUST overwrite inbound `X-Forwarded-*` (so a client cannot spoof), and
- direct access to the app port MUST be network-restricted to the proxy.
Without those, trusting forwarding headers would let a client forge its address/scheme.

### 9. Private signing-key file permissions (cross-platform)
`Ed25519Signer` checks the private-key file on load:
- **POSIX:** group/other-readable → **fail-closed outside `local`/`test`**, warn under
  `local`/`test`.
- **Non-POSIX (e.g. Windows):** POSIX bits are unavailable; the check is explicitly skipped (logged)
  and protection relies on **platform ACLs** — a documented reliance, not a silent assumption.
The key contents are never read or logged by this check. KMS/HSM integration remains production
design-only (ADR 0009).

The permission-evaluation **decision** is extracted into a pure, platform-independent function
(`SigningKeyPermissionPolicy.evaluate(Set<PosixFilePermission>, localOrTest)` →
`SAFE | UNSAFE_WARN | UNSAFE_FAIL_CLOSED`) that does no filesystem I/O. This makes the policy
unit-testable on every platform (including Windows), while the OS-specific act of *reading* the
permissions stays in `Ed25519Signer` and is exercised by an integration test that is conditionally
skipped on non-POSIX filesystems.

## What is explicitly NOT in this slice
- **Rate limiting / brute-force throttling** — acknowledged as a production requirement but
  **deferred with rationale** (belongs at the gateway/proxy tier; single-instance prototype). See
  threat-model.md.
- **OAuth2/OIDC JWT authentication, Actuator, metrics, structured logging** — separate commits.

## Consequences
- Backward compatible: API keys, endpoint contracts, and the 135 existing tests are unchanged. The
  only behavioral change is that the docs surface is no longer public by default and oversized/
  pathological bodies are now rejected (with generous defaults).
- New knobs (`audit.limits.*`, `audit.docs.*`) all have safe defaults.

## Validation
New tests: oversized declared-length body → 413; oversized chunked body → 413; at-limit body →
201; excessive JSON depth/string/number → 400; error bodies never echo the payload; redactable
count/path/syntax → 400; security headers present; HSTS absent over HTTP; forwarded headers not
trusted by default; docs disabled by default / public under local / ADMIN-only when
enabled-but-private; POSIX key-permission fail-closed vs warn (skipped on non-POSIX). Full
`./mvnw clean verify` remains green.

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-19.
