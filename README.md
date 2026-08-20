# Tamper-Evident Audit Log Service

> **Project status: COMPLETE (Scenarios A, B, C) + post-review hardening.**
> Runnable end-to-end on Java 21 / Spring Boot 4.1 / PostgreSQL 16 with **267 passing tests**
> (unit + Testcontainers integration; 3 POSIX-only signing-key-permission tests are skipped on
> non-POSIX filesystems). See [docs/architecture.md](docs/architecture.md),
> [docs/final-engineering-summary.md](docs/final-engineering-summary.md), and the reviewer-facing
> [docs/security-auth-observability-improvements.md](docs/security-auth-observability-improvements.md).
>
> A **post-review security/auth/observability hardening pass** (branch
> `feature/security-observability-hardening`, ADRs 0010–0013) was added **after** the original
> submission — see [ATTESTATION.md](ATTESTATION.md).

A service that records an **append-only** history of events and makes any modification
or deletion of past records **detectable** via a cryptographic hash chain. Built as an
interview assignment demonstrating AI-assisted engineering with the engineer owning
correctness, design, and authorship.

---

## Current stage

| Stage | State |
|---|---|
| Requirement analysis & assumptions | Done (docs) |
| Design & decision records | Done (`docs/decisions/` — ADRs 0001–0013) |
| Build + local runtime | Done (`pom.xml`, entry point, config, Compose, Maven Wrapper) |
| Database schema / Flyway migrations | **V1–V3** — event chain, amendment chain, archive + manifest |
| Hashing | Canonical serialization + SHA-256 content hash (ADR 0003) |
| Write API | `POST /api/v1/audit/events` — transactional append, `SELECT ... FOR UPDATE` chain lock (ADR 0004) |
| Read API | `GET /api/v1/audit/events` — filtered, cursor-paginated, bounded search (ADR 0005) |
| Verify API | `GET /api/v1/audit/verify` — full chain walk, 10 violation types (ADR 0005) |
| Security | **Dual-mode auth** — `X-API-Key` (server-side roles) + optional OAuth2/OIDC JWT (off by default); fail-closed `denyAll()`; request/HTTP hardening (ADRs 0006, 0010, 0011) |
| Observability | Actuator health probes + Prometheus domain metrics + ECS structured logging + correlation IDs (ADR 0012) |
| Compliance (Scenario C slice) | `GET /api/v1/compliance/access-report` — client-account access (success + denied), actor/account/outcome/time filters |
| Redaction (Scenario B) | `POST /api/v1/audit/events/{seq}/redact` (ADMIN) — salted-commitment redaction + amendment chain; chain stays intact (ADR 0007) |
| Retention/archival (Scenario B) | `POST /api/v1/audit/retention/archive` (ADMIN) — move oldest prefix to archive + manifest + ARCHIVE amendment; verify reads active+archive as one chain (ADR 0008) |
| Verifiable export (Scenario B) | `GET /api/v1/audit/export?resourceId=\|actorId=` — Ed25519-signed bundle + standalone `ExportVerifyMain` verifier (ADR 0009) |
| Tests | **267 total** (3 POSIX-only skipped on non-POSIX) — core Scenario A/B/C coverage plus request-hardening, dual-mode JWT, and observability suites (see [docs/testing-strategy.md](docs/testing-strategy.md)) |
| Runnable end-to-end | **Scenarios A + B + compliance + hardening** — append, query, verify, tamper-detect, redact, archive, signed export (verifies offline), compliance report, health probes, Prometheus scrape |

---

## Getting started (local)

The service runs end-to-end: `docker compose up` starts PostgreSQL 16, `./mvnw spring-boot:run`
starts the app (Flyway applies migrations V1–V3), and the full API (append, query, verify, redact,
archive, signed export, compliance report) is available. See [docs/demo.md](docs/demo.md) for a
guided walkthrough.

### Prerequisites
- **JDK 21** (Spring Boot 4.1 supports Java 17–26; this project targets 21).
- **Maven is NOT required** — the repo ships a **Maven Wrapper** pinned to Apache Maven
  3.9.9. Use `./mvnw` (macOS/Linux) or `mvnw.cmd` (Windows); the wrapper downloads the
  correct Maven automatically on first use.
- **Docker + Docker Compose** — required to run the local PostgreSQL, and to run the
  Testcontainers-based tests (they start a throwaway PostgreSQL container).

### 1. Start PostgreSQL
```
cp .env.example .env         # optional; compose has safe local defaults without it
docker compose up -d         # starts PostgreSQL 16 only (no app container yet)
docker compose ps            # wait until 'audit-postgres' is healthy
```
> **Port 5432 already in use?** If you already run a local PostgreSQL, publish the
> container on another host port and point the app at it:
> ```
> POSTGRES_PORT=5433 docker compose up -d
> AUDIT_DB_URL=jdbc:postgresql://localhost:5433/audit ./mvnw spring-boot:run
> ```

### 2. Run the application (via the Maven Wrapper, not a container)
```
# macOS/Linux
./mvnw spring-boot:run
# Windows
mvnw.cmd spring-boot:run
```
The app boots against the Compose PostgreSQL using the defaults in
`src/main/resources/application.yml` and serves the full API (append, query, verify, redact, archive,
signed export, compliance report) plus the observability endpoints (health probes, Prometheus). For a
guided walkthrough incl. the security-hardening checks, see [docs/demo.md](docs/demo.md).

> **Note:** outside the `local`/`test` profiles the service **fails closed at startup** if no Ed25519
> export signing key is configured (ADR 0009). Run with `--spring.boot.run.profiles=local` (or
> `-Dspring-boot.run.profiles=local`) locally to use the ephemeral dev signing key.

### 3. Stop PostgreSQL
```
docker compose down          # stops & removes the container; PRESERVES the data volume
docker compose down -v       # also DELETES the local database volume (data is lost)
```
> Data lives in the named volume `audit-pg-data`. `docker compose down` keeps it (your
> data survives a restart); `docker compose down -v` removes it. The PostgreSQL image's
> `POSTGRES_*` initialization only runs against a **new, empty** volume — so to pick up
> changed init credentials you must recreate the volume with `down -v`.

### Configuration & how it is (and isn't) loaded — read this
- **`application.yml`** (committed) is always loaded. It contains only **local-only
  placeholder** values via environment-variable defaults — no secrets. Its defaults point
  at the Docker Compose PostgreSQL.
- **`application-local.yml.example` is only a template.** While it keeps the `.example`
  suffix it is **never loaded** by Spring. To use it you must:
  1. copy it: `cp src/main/resources/application-local.yml.example src/main/resources/application-local.yml`
     (the real `application-local.yml` is git-ignored), **and**
  2. activate the `local` profile so Spring picks it up, e.g.
     `./mvnw spring-boot:run -Dspring-boot.run.profiles=local`
     or `SPRING_PROFILES_ACTIVE=local ./mvnw spring-boot:run`.
  Alternatively, skip the file entirely and just supply the environment variables
  (`AUDIT_DB_URL`, `AUDIT_DB_USERNAME`, `AUDIT_DB_PASSWORD`, …) directly.
- **`.env` is for Docker Compose only.** Docker Compose auto-reads `.env` to configure the
  **container** (see `docker-compose.yml`). Those variables are **not** automatically
  exported into a separately launched Maven/JVM process. If you change DB settings in
  `.env`, mirror them for the app via environment variables or `application-local.yml`
  (the `AUDIT_DB_*` entries in `.env.example` show the intended values to keep in sync).

### Authentication
All `/api/v1/**` endpoints require authentication. Two modes are supported and can run together
(dual-mode); roles are **always resolved server-side** — the client never sends a role.

**API keys (default).** An `X-API-Key` header maps to a role (WRITER / COMPLIANCE_READER / ADMIN).
Supply keys via env vars (`AUDIT_WRITER_KEY`, `AUDIT_COMPLIANCE_KEY`, `AUDIT_ADMIN_KEY`); unset keys
are simply inaccessible. Each key may have a stable, non-secret **id** (`audit.security.api-keys[].id`)
used only in sanitized auth logs. Missing/invalid key → 401; wrong role → 403.

**OAuth2/OIDC JWT (optional, off by default).** Set `audit.security.jwt.enabled=true` with an
`issuer-uri` (or `jwk-set-uri`) and at least one `audiences` entry. Tokens are validated for
signature, an algorithm allow-list (`allowed-algorithms`, default RS256/ES256), issuer, audience,
and exp/nbf. Only trusted scopes map to roles: `audit.write → WRITER`, `audit.read →
COMPLIANCE_READER`, `audit.admin → ADMIN`. Client `roles`/`authorities` claims are ignored; there is
no default role. Enabling JWT with incomplete config **fails startup**. Send the token as
`Authorization: Bearer <token>`.

> **Dual-credential requests are rejected (400).** Supplying both a `Bearer` token and an
> `X-API-Key` is ambiguous and refused; an invalid Bearer token never falls back to API-key auth.

> **Rotation/revocation** in this prototype is a **configuration update + restart/reload** — there is
> no runtime revocation API. JWT signing-key rotation is handled by the authorization server; the
> service picks up new keys from the JWKS.

Example (API key):
```
curl -H "X-API-Key: $AUDIT_WRITER_KEY" -H "Content-Type: application/json" \
     -d '{"eventType":"USER_LOGIN","actorId":"u1","actorType":"USER",
          "resourceType":"CLIENT_ACCOUNT","resourceId":"acct-1","outcome":"SUCCESS"}' \
     http://localhost:8080/api/v1/audit/events
```

### Notes
- Secrets are never committed. `application.yml`, `.env.example`, and
  `application-local.yml.example` contain only **local-only** placeholder values.
  Test-only API keys live in `src/test/resources/application-test.yml` (overrides only; the suite
  loads the main `application.yml` first, then applies these under the `test` profile) and are
  clearly non-production.
  `application-local.yml` is strictly for a developer's **local** machine (git-ignored).
- **Non-local environments do not use `application-local.yml` or committed defaults.**
  Real credentials there are supplied via **protected environment injection or a secret
  manager** (e.g. Docker/K8s secrets, Vault, a cloud secret manager) — never checked into
  the repository.
- Decisions and how versions/schema were verified are recorded under
  [docs/decisions/](docs/decisions/) (ADRs 0001–0013).

---

## Stack

- **Language / runtime:** Java 21
- **Framework:** Spring Boot 4.1.0 (BOM-governed dependencies; see `docs/decisions/0001-*`)
- **Build:** Maven (Maven Wrapper pinned to 3.9.9)
- **Persistence:** PostgreSQL 16 + Spring Data JPA, schema managed by Flyway (V1–V3)
- **API docs:** springdoc-openapi 3.1.0 (Boot 4.x line), gated by `audit.docs.*`
- **AuthN/Z:** `X-API-Key` server-side roles + optional OAuth2/OIDC JWT resource server (off by
  default); Spring Security fail-closed `denyAll()`
- **Hashing:** SHA-256 over a canonical serialization; Ed25519 signed export (dedicated key)
- **Observability:** Spring Boot Actuator + Micrometer/Prometheus + native ECS structured logging
- **Testing:** JUnit 5, Testcontainers (real PostgreSQL 16), Nimbus JOSE for local JWT test keys
- **Local orchestration:** Docker Compose (PostgreSQL)

---

## Implemented capabilities

All three assignment scenarios are implemented, plus a post-review hardening pass.

### Scenario A — Core audit log service
- Write API to append event records (`eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, `timestamp`). Append-only: no update or delete API.
- Query API with filtering (`actorId`, `resourceType` + `resourceId`, `eventType`, time range) and pagination.
- Hash-chain tamper evidence: each record carries a hash of its own content and of the preceding record.
- `GET /audit/verify` endpoint that walks the full chain and reports whether it is intact, and if broken, the first inconsistency and violation type.

### Scenario B — Retention & redaction (extension)
- Configurable retention: old records archivable/soft-deletable without producing false-positive chain breaks.
- Structured payload redaction of sensitive fields without invalidating the hash chain.
- Verifiable bulk export bundle a recipient can independently verify.

### Scenario C — Compliance reporting (ambiguous requirement)
- Clarification and normalization of "regulators need to be able to audit access to client account data," followed by a concrete design and a scoped partial implementation.

---

## Repository layout (current)

```
.
├── README.md                     <- this file
├── ATTESTATION.md                <- authorship attestation
├── mvnw, mvnw.cmd                <- Maven Wrapper (pinned to Apache Maven 3.9.9)
├── .mvn/wrapper/maven-wrapper.properties  <- wrapper config (committed)
├── pom.xml                       <- Maven build (Spring Boot 4.1.0 parent; BOM-governed deps)
├── docker-compose.yml            <- local PostgreSQL 16 only (app runs via Maven)
├── .env.example                  <- local-only env placeholders for Compose (copy to .env)
├── .gitignore
├── src/
│   ├── main/
│   │   ├── java/com/raghavendra/audit/     <- event, amendment, redaction, retention, verify,
│   │   │                                      export, compliance, and common/{hash,security,
│   │   │                                      security/jwt,web,observability,config} packages
│   │   └── resources/
│   │       ├── application.yml              <- base config (env placeholders; actuator; ECS logging)
│   │       ├── application-local.yml.example
│   │       ├── application-proxy.yml        <- proxy profile: forwarded-header trust
│   │       └── db/migration/                <- Flyway V1 (event chain), V2 (amendments), V3 (archive)
│   └── test/
│       ├── java/com/raghavendra/audit/...   <- unit + Testcontainers integration tests
│       └── resources/application-test.yml   <- test overrides only (loaded on top of main)
├── scripts/                                 <- demo.sh, generate-export-keypair.sh
└── docs/
    ├── decisions/                           <- ADRs 0001–0013
    ├── requirements/                        <- scenario-a/b/c requirement analyses
    ├── architecture.md, threat-model.md, testing-strategy.md, observability.md,
    ├── security-auth-observability-improvements.md, scenario-c-design.md, demo.md,
    ├── assumptions.md, final-engineering-summary.md, ai-usage-log.md
```

### Key documents
- [docs/architecture.md](docs/architecture.md) — components, data model, two-chain design, API + authz matrix, hashing.
- [docs/final-engineering-summary.md](docs/final-engineering-summary.md) — plan, artifacts, risks/trade-offs, assumptions, limitations.
- [docs/testing-strategy.md](docs/testing-strategy.md) — coverage and what's out of scope.
- [docs/threat-model.md](docs/threat-model.md) — adversaries, mitigations, residual risks.
- [docs/scenario-c-design.md](docs/scenario-c-design.md) — compliance-reporting clarification + design.
- [docs/demo.md](docs/demo.md) — end-to-end walkthrough; [scripts/demo.sh](scripts/demo.sh) runs it.
- [docs/security-auth-observability-improvements.md](docs/security-auth-observability-improvements.md) — reviewer-facing post-review hardening summary.
- [docs/observability.md](docs/observability.md) — actuator/metrics/logging/correlation-ID operational guide.
- [docs/decisions/](docs/decisions/) — ADRs 0001–0013; [docs/ai-usage-log.md](docs/ai-usage-log.md) — AI traceability.

---

## Authorship & AI use

This is individual work. AI assistants were used for planning, drafting, and design
review; the engineer directs the work, reviews every output, and owns correctness and
authorship. See `docs/ai-usage-log.md` for an honest, itemized record of what AI
proposed, what was accepted, modified, or rejected, and why. See `ATTESTATION.md` for
the formal attestation.
