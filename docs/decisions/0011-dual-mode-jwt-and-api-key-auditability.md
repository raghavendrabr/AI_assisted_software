# ADR 0011 — Conditional Dual-Mode JWT Authentication & API-Key Auditability

- **Status:** Accepted
- **Date:** 2026-08-19
- **Context:** The prototype authenticated only via static `X-API-Key`. Reviewer feedback asked for a
  production-credible authentication story. This ADR records Commit B: an optional OAuth2/OIDC JWT
  resource-server that runs **alongside** API keys (dual-mode), plus non-secret key IDs for
  auditable, sanitized authentication logging. Observability/metrics are Commit C and are out of
  scope here.

## Decision

### Dual-mode, conditional JWT
- A new namespace `audit.security.jwt.*` (`JwtProperties`) controls JWT: `enabled` (default
  **false**), `issuer-uri`, optional `jwk-set-uri`, `audiences`, `allowed-algorithms`, and a
  configurable `scope-roles` map.
- **We deliberately do NOT bind Spring Boot's standard
  `spring.security.oauth2.resourceserver.jwt.issuer-uri`.** Binding an empty placeholder there would
  trigger Boot's auto-configured resource server (and a startup round-trip to the issuer) even when
  JWT is meant to be off. Instead `JwtSecurityConfig` builds the `JwtDecoder` itself, only when the
  configuration is complete.
- **Conditional activation:**
  - disabled (default) or incomplete → **API-key-only mode**; no resource server is wired.
  - enabled **and** complete (a key source + ≥1 audience) → a hardened `NimbusJwtDecoder` is built.
  - **enabled but incomplete** → **fatal startup error** (`@PostConstruct` validation) — a
    half-configured resource server can never start and silently accept tokens.
  - When JWT is disabled, a `Bearer` token is an unrecognized credential → **401**.

### JWT validation (all enforced)
`AuditJwtDecoderFactory` builds a decoder that validates, for every token:
1. **cryptographic signature** against the issuer/JWK-set keys;
2. an explicit **algorithm allow-list** (`allowed-algorithms`, default RS256+ES256) — any other
   `alg` is rejected;
3. **issuer** (`iss` == `issuer-uri`);
4. **audience** (`aud` intersects `audiences`);
5. **expiration** (`exp`) and **not-before** (`nbf`) via the timestamp validator;
6. structural validity (enforced inside Nimbus decoding).

### Scope → role mapping (strict)
`JwtScopeRoleConverter` maps **only trusted scopes** to authorities:

| Scope | Authority |
|---|---|
| `audit.write` | `ROLE_WRITER` |
| `audit.read` | `ROLE_COMPLIANCE_READER` |
| `audit.admin` | `ROLE_ADMIN` |

- Scopes are read from the standard `scope` (space-delimited) or `scp` (array) claims **only**.
- Any client-supplied `roles`/`authorities`/`groups` claim is **ignored** — a client cannot
  self-assign a role.
- **No default role:** a token with no mapped scope has no authority, so the existing authorization
  matrix denies it (403). Both mechanisms reuse the same matrix and the `denyAll()` fallback.

### Dual-credential rules
- **API key alone** → existing behavior.
- **Valid Bearer alone** → JWT authentication.
- **Both Bearer AND `X-API-Key`** → rejected with a safe **400** (`DualCredentialGuardFilter`,
  before either auth filter) — never silently pick one.
- **Invalid Bearer must not fall back to an API key.** The `ApiKeyAuthFilter` (a) does nothing if a
  JWT already authenticated the request, and (b) does nothing if any `Bearer` header is present — so
  an invalid Bearer results in 401, never an API-key success.
- Filter order: `RequestBodySizeLimitFilter` → `DualCredentialGuardFilter` → `ApiKeyAuthFilter` →
  (JWT `BearerTokenAuthenticationFilter` when enabled) → authorization matrix → `denyAll()`.
- **401/403 handlers use `setStatus`, not `sendError`.** `sendError` triggers an internal ERROR
  dispatch to `/error`, which re-enters the security chain as anonymous, hits `denyAll()`, and would
  overwrite an authenticated-but-forbidden **403 with a 401**. Writing the status directly (no error
  forward) makes an authenticated wrong-role/scope request correctly return 403 over real HTTP. (This
  also corrects the same latent behavior for the API-key-only path.)

### Response-header protocol
- **`WWW-Authenticate: Bearer` on failed JWT.** The resource server installs its own
  `BearerTokenAuthenticationEntryPoint` for Bearer requests, so an invalid / expired / malformed /
  wrong-signature token returns **401 with `WWW-Authenticate: Bearer error="invalid_token"…`** (RFC
  6750). The challenge names only the error reason — never the token. The API-key / no-credential
  entry point is the bare-401 (my global entry point), so an **API-key or no-credential 401 does NOT
  advertise Bearer** — the two paths are correctly distinguished.
- **Insufficient scope stays 403.** An authenticated JWT lacking the required scope returns **403**
  (access-denied), never downgraded to 401, and carries no Bearer challenge.
- **Both-credentials 400** is a structured `ApiError` (`application/json`, `{status,error,message}`)
  echoing neither credential, with no `WWW-Authenticate` header (a request-shape error, not a
  challenge).

### API-key auditability
- Each key gains a stable, **non-secret** `id` (`audit.security.api-keys[].id`). When absent, a
  synthetic `<role>-key` id is derived — so the **existing writer/reader/admin config keeps working
  unchanged**.
- Key ids are validated at startup: safe characters `[A-Za-z0-9._-]`, length ≤ 64, and **uniqueness**
  (duplicate ids fail startup). Invalid/duplicate ids are a fatal startup error.
- The id is used **only** in sanitized logs — never the key or its digest.

### Sanitized authentication logging
- `AuthEventLogger` logs: auth **method** (API_KEY/JWT/BOTH_REJECTED/NONE), **result**, a
  developer-authored **reason** constant, the **requestId** from MDC (a correlation-id filter arrives
  in Commit C; until then the field is simply absent), and a **non-secret principal** (the API-key id
  or a bounded JWT-subject fingerprint).
- **Never logged:** the API key; the **raw API-key SHA-256 digest is never logged** either (the
  API-key principal is always the configured non-secret key id); the JWT (header/body/signature) or
  the full claims map; and **arbitrary raw JWT subject text is not logged** — a JWT identity is
  represented only by a bounded, stable **fingerprint** (`jwt:<16 hex>`, a truncated SHA-256 of the
  subject), so the same subject can be correlated across log lines without writing the subject
  string.
- Every variable field is sanitized (control characters — incl. CR/LF — stripped, length bounded) to
  prevent **log injection / forged log lines**.
- **Metric instrumentation is deferred to Commit C.**

## Honest limitations
- **Rotation / revocation is configuration + restart/reload.** Keys and their ids come from
  configuration; there is **no runtime revocation API** in this prototype. Rotating or revoking a key
  requires a config change and an application restart/reload. (JWT rotation is the authorization
  server's concern; the service picks up new signing keys from the JWKS.)
- **Issuer / JWKS availability.** When JWT is enabled with an `issuer-uri` only, the JWKS is
  discovered from the issuer and must be reachable; a `jwk-set-uri` can be supplied to pin it. If the
  key source is unreachable at runtime, token validation fails closed (401), not open.
- **No live IdP in tests.** Tests generate local RSA keys, serve a real JWK set from an in-test HTTP
  endpoint, and mint real signed tokens, so the real `NimbusJwtDecoder` performs genuine validation —
  without contacting any external identity provider.

## Consequences
- Additive and backward compatible: API keys and every existing endpoint contract are unchanged;
  JWT is opt-in via configuration. If `audit.security.jwt.enabled` is false (default), behavior is
  identical to before except for the new key-id field and sanitized auth logs.
- New dependency: `spring-boot-starter-security-oauth2-resource-server` (BOM-managed; the older
  `spring-boot-starter-oauth2-resource-server` is deprecated in Boot 4.1 in favor of this
  `security-`-prefixed coordinate).

## Validation
Tests use the real Bearer filter + real `NimbusJwtDecoder` with locally-signed tokens (not only
`spring-security-test` `jwt()`). Covered: valid API key still works; valid JWT per trusted scope;
expired; not-before; malformed; wrong-signature; disallowed-algorithm; wrong-issuer; wrong-audience;
missing scopes (403); insufficient scope (403); roles-claim-only (403); unknown scopes grant nothing;
both-credentials (400); invalid-Bearer-no-fallback; JWT-disabled + Bearer (401); JWT-disabled + API
key still works; enabled-but-incomplete fails startup; duplicate/invalid key ids fail startup; and no
credential/token/key/digest appears in logs or responses. `./mvnw clean verify` green.

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-19.
