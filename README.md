# Tamper-Evident Audit Log Service

> **Project status: COMPLETE (Scenarios A, B, C).**
> Runnable end-to-end on Java 21 / Spring Boot 4.1 / PostgreSQL 16 with 135 passing tests
> (unit + Testcontainers integration). See [docs/architecture.md](docs/architecture.md) and
> [docs/final-engineering-summary.md](docs/final-engineering-summary.md).

A service that records an **append-only** history of events and makes any modification
or deletion of past records **detectable** via a cryptographic hash chain. Built as an
interview assignment demonstrating AI-assisted engineering with the engineer owning
correctness, design, and authorship.

---

## Current stage

| Stage | State |
|---|---|
| Requirement analysis & assumptions | Done (docs) |
| Design & decision records | In progress (`docs/decisions/` — ADR 0001 versions, ADR 0002 schema) |
| Build + local runtime scaffolding | Done (`pom.xml`, entry point, config, Compose, Maven Wrapper) |
| Database schema / Flyway migrations | **V1** — `audit_event` + `audit_chain_head` tables + seed row |
| Hashing | Canonical serialization + SHA-256 content hash (ADR 0003) |
| Write API | `POST /api/v1/audit/events` — transactional append, `SELECT ... FOR UPDATE` chain lock (ADR 0004) |
| Read API | `GET /api/v1/audit/events` — filtered, cursor-paginated, bounded search (ADR 0005) |
| Verify API | `GET /api/v1/audit/verify` — full chain walk, 6 violation types (ADR 0005) |
| Security | **API-key auth** (`X-API-Key`) → server-side roles WRITER / COMPLIANCE_READER / ADMIN, per-endpoint authorization (ADR 0006) |
| Compliance (Scenario C slice) | `GET /api/v1/compliance/access-report` — client-account access (success + denied), actor/account/outcome/time filters |
| Redaction (Scenario B) | `POST /api/v1/audit/events/{seq}/redact` (ADMIN) — salted-commitment redaction + amendment chain; chain stays intact (ADR 0007) |
| Retention/archival (Scenario B) | `POST /api/v1/audit/retention/archive` (ADMIN) — move oldest prefix to archive + manifest + ARCHIVE amendment; verify reads active+archive as one chain (ADR 0008) |
| Verifiable export (Scenario B) | `GET /api/v1/audit/export?resourceId=\|actorId=` — Ed25519-signed bundle + standalone `ExportVerifyMain` verifier (ADR 0009) |
| Tests | 135 total — hashing (28), V1 schema (11), append (12), search (8), verify (10), redaction (19), retention (19), export (16), security (19), compliance (5), handler (2), context (1) |
| Runnable end-to-end | **Scenarios A + B + compliance** — append, query, verify, tamper-detect, redact, archive, signed export (verifies offline), compliance report |

API examples and test-status badges will be added **only once the corresponding code
exists**. They are intentionally omitted now to avoid implying functionality that has
not been built.

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
`src/main/resources/application.yml`. It currently exposes no functional audit endpoints.

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
All `/api/v1/**` endpoints require an `X-API-Key` header. Keys map to roles **server-side**
(WRITER / COMPLIANCE_READER / ADMIN) — the client never sends a role. Supply keys via env vars
(`AUDIT_WRITER_KEY`, `AUDIT_COMPLIANCE_KEY`, `AUDIT_ADMIN_KEY`); unset keys are simply
inaccessible. Missing/invalid key → 401; wrong role → 403. Example:
```
curl -H "X-API-Key: $AUDIT_WRITER_KEY" -H "Content-Type: application/json" \
     -d '{"eventType":"USER_LOGIN","actorId":"u1","actorType":"USER",
          "resourceType":"CLIENT_ACCOUNT","resourceId":"acct-1","outcome":"SUCCESS"}' \
     http://localhost:8080/api/v1/audit/events
```

### Notes
- Secrets are never committed. `application.yml`, `.env.example`, and
  `application-local.yml.example` contain only **local-only** placeholder values.
  Test-only API keys live in `src/test/resources/application.yml` and are clearly non-production.
  `application-local.yml` is strictly for a developer's **local** machine (git-ignored).
- **Non-local environments do not use `application-local.yml` or committed defaults.**
  Real credentials there are supplied via **protected environment injection or a secret
  manager** (e.g. Docker/K8s secrets, Vault, a cloud secret manager) — never checked into
  the repository.
- Decisions and how versions/schema were verified are recorded under
  [docs/decisions/](docs/decisions/) (ADR 0001 — versions; ADR 0002 — audit-chain schema).

---

## Intended stack (planned, not yet present)

- **Language / runtime:** Java 21
- **Framework:** Spring Boot 4.1.x (current stable GA line; see `docs/assumptions.md` for the version rationale)
- **Build:** Maven
- **Persistence:** PostgreSQL 16 + Spring Data JPA, schema managed by Flyway migrations
- **API docs:** springdoc-openapi 3.1.x (the springdoc line that supports Spring Boot 4.x)
- **Hashing:** SHA-256 over a canonical serialization of event fields
- **Export signing:** Ed25519 (dedicated signing key, separate from API auth)
- **Testing:** JUnit 5, Mockito, Testcontainers (real PostgreSQL)
- **Local orchestration:** Docker Compose (planned)

> Exact dependency versions will be pinned in `pom.xml` when the project is scaffolded,
> and the choices recorded in an Architecture Decision Record.

---

## Planned capabilities

These map to the three assignment scenarios. **None are implemented yet.**

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
│   └── main/
│       ├── java/com/raghavendra/audit/
│       │   └── AuditLogServiceApplication.java   <- minimal Spring Boot entry point
│       └── resources/
│           ├── application.yml                    <- base config (env-var placeholders, no secrets)
│           ├── application-local.yml.example      <- example local override (copy to application-local.yml)
│           └── db/migration/
│               └── V1__create_audit_chain_foundation.sql  <- audit_event + audit_chain_head + seed
└── docs/
    ├── decisions/
    │   ├── 0001-technology-versions.md  <- ADR: verified dependency versions & sources
    │   └── 0002-audit-chain-schema.md   <- ADR: audit-chain schema & constraints (V1)
    ├── requirements/
    │   ├── scenario-a.md          <- assignment requirements vs. our assumptions (A)
    │   ├── scenario-b.md          <- assignment requirements vs. our assumptions (B)
    │   └── scenario-c.md          <- ambiguous requirement clarification (C)
    ├── assumptions.md             <- cross-cutting assumptions & open questions
    ├── ai-usage-log.md            <- honest record of AI use in planning/design
    └── final-engineering-summary.md  <- outline, to be filled in as work proceeds
```

### Key documents
- [docs/architecture.md](docs/architecture.md) — components, data model, two-chain design, API + authz matrix, hashing.
- [docs/final-engineering-summary.md](docs/final-engineering-summary.md) — plan, artifacts, risks/trade-offs, assumptions, limitations.
- [docs/testing-strategy.md](docs/testing-strategy.md) — coverage and what's out of scope.
- [docs/threat-model.md](docs/threat-model.md) — adversaries, mitigations, residual risks.
- [docs/scenario-c-design.md](docs/scenario-c-design.md) — compliance-reporting clarification + design.
- [docs/demo.md](docs/demo.md) — end-to-end walkthrough; [scripts/demo.sh](scripts/demo.sh) runs it.
- [docs/decisions/](docs/decisions/) — ADRs 0001–0009; [docs/ai-usage-log.md](docs/ai-usage-log.md) — AI traceability.

---

## Authorship & AI use

This is individual work. AI assistants were used for planning, drafting, and design
review; the engineer directs the work, reviews every output, and owns correctness and
authorship. See `docs/ai-usage-log.md` for an honest, itemized record of what AI
proposed, what was accepted, modified, or rejected, and why. See `ATTESTATION.md` for
the formal attestation.
