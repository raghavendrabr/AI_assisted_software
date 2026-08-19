# ADR 0006 — API-Key Security & Compliance Reporting

- **Status:** Accepted (pending engineer sign-off)
- **Date:** 2026-08-18
- **Context:** Replace the temporary permit-all security (ADR 0004) with real server-side
  API-key authentication and per-endpoint authorization, and implement the Scenario C
  in-scope slice: a compliance access report over client-account data.

## Authentication — `X-API-Key`, server-side role resolution

- The client sends **only** the API key in the `X-API-Key` header. It never sends a role.
- Keys → roles are configured via `audit.security.api-keys` (env-injected; **no real keys are
  committed** — `application.yml` uses `${AUDIT_*_KEY:}` placeholders that resolve to empty and
  are skipped when unset).
- `ApiKeyService` resolves a presented key to its role by **SHA-256 digest + constant-time
  compare** (`MessageDigest.isEqual`); raw keys are not retained in the lookup map.
- `ApiKeyAuthFilter` (a `OncePerRequestFilter` before the username/password filter) sets an
  authenticated token with authority `ROLE_<role>` on success; on missing/invalid key it sets
  nothing and Spring Security rejects the request.
- **401 vs 403:** unauthenticated (no/invalid key) → **401** via the authentication entry
  point; authenticated but insufficient role → **403** via the access-denied handler.
- Stateless (`SessionCreationPolicy.STATELESS`), CSRF disabled (no browser session).

## Roles & authorization matrix

Roles are **distinct capabilities**; ADMIN is granted the union explicitly per rule, not by
inheritance.

| Endpoint | Method | Allowed roles |
|---|---|---|
| `/api/v1/audit/events` | POST | WRITER, ADMIN |
| `/api/v1/audit/events` | GET | COMPLIANCE_READER, ADMIN |
| `/api/v1/audit/verify` | GET | COMPLIANCE_READER, ADMIN |
| `/api/v1/compliance/access-report` | GET | COMPLIANCE_READER, ADMIN |
| `/v3/api-docs/**`, `/swagger-ui/**`, `/swagger-ui.html` | GET | public (ONLY these OpenAPI paths) |
| anything else | any | **`denyAll()`** — fail-closed |

**Fail-closed default:** the chain ends with `anyRequest().denyAll()`, not `authenticated()`.
A newly added endpoint is denied (403 authenticated / 401 anonymous) until an explicit rule
grants it, so it can never be accidentally public. Only the three OpenAPI/Swagger paths above
are public.

## Hardening — key-config validation & no key leakage

- **Fail-fast at startup** (`ApiKeyService` constructor): a key mapped to more than one role,
  or the same key configured twice, throws and aborts startup. The service never silently picks
  the "first matching" role for an ambiguous key.
- **Whitespace-only / blank keys are treated as unset** and skipped (so unset env placeholders
  are inactive, and two blank placeholders never register as a duplicate/conflict).
- **No key in errors or logs:** validation exception messages exclude the key and its digest;
  the auth filter logs nothing; the authenticated principal is the ROLE only (`api-key:<role>`),
  never the key/digest; 401/403 responses carry only a status code.

**Prototype boundary:** static API keys are prototype-grade. Production would use OAuth2/OIDC +
mTLS, per-key rotation/expiry, and a secret manager — documented as future work, not built.

## Compliance access report (Scenario C in-scope slice)

`GET /api/v1/compliance/access-report` — an immutable, independently-verifiable report of access
to **client-account data**, scoped to events whose `resourceType` equals the configured
`audit.compliance.client-account-resource-type` (default `CLIENT_ACCOUNT`).

- **Includes BOTH successful and denied access** (distinguished by the `outcome` field).
- **Filters:** `actorId`, `accountId` (the account `resourceId`), `outcome`, and time range
  (`from` inclusive / `to` exclusive; `from` must be before `to`, else 400).
- Each entry answers **who / which account / when / how (action) / why (businessReason) /
  whether it succeeded**, and carries the record's `sequenceNumber` + `contentHash` so it ties
  back to the tamper-evident chain (a recipient can cross-check against `/audit/verify`).
- Reuses the bounded, cursor-paginated query service (limit + 1, MAX_LIMIT), so the report
  inherits stable pagination and the size bound.

This is the **implemented** portion of Scenario C. The clarified requirement and the explicit
scope-out (regulator identity federation, scheduled/PDF reports, external delivery, statistical
completeness) are documented in `docs/requirements/scenario-c.md`.

## Validation

- `ApiKeySecurityIntegrationTest` (9): missing/invalid key → 401; wrong-role key → 403 on each
  protected endpoint; correct role → 2xx; ADMIN can do all four operations; an **unlisted
  endpoint is denied** (403 with ADMIN key, 401 without) — proving the fail-closed default.
- `ApiKeyServiceValidationTest` (5): multi-role key and duplicate key fail fast (without leaking
  the key); whitespace-only keys are skipped; two blank placeholders don't conflict; distinct
  keys resolve to distinct roles.
- `ComplianceReportIntegrationTest` (5): report includes successful + denied client-account
  access and excludes non-client-account events; filters by outcome and by actor+account;
  entries carry the content hash; inverted time range → 400.
- Existing tests updated to send the appropriate `X-API-Key`.

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.
