# Tamper-Evident Audit Log Service

> **Project status: SCAFFOLDING STAGE.**
> The project now has a Maven build, a minimal Spring Boot entry point, base
> configuration, and a local PostgreSQL via Docker Compose. **There are still no
> database tables, Flyway migrations, JPA entities, repositories, controllers,
> services, hash-chain logic, or business functionality — and no functional tests
> beyond the default Spring context check.** The sections below describe the
> **intended** stack and **planned** capabilities; only the scaffolding described in
> "Getting started" actually exists today. No APIs work yet.

A service that records an **append-only** history of events and makes any modification
or deletion of past records **detectable** via a cryptographic hash chain. Built as an
interview assignment demonstrating AI-assisted engineering with the engineer owning
correctness, design, and authorship.

---

## Current stage

| Stage | State |
|---|---|
| Requirement analysis & assumptions | Done (docs) |
| Design & decision records | In progress (`docs/decisions/` — ADR 0001 records versions) |
| Build + local runtime scaffolding | Done (this step: `pom.xml`, entry point, config, Compose) |
| Database schema / Flyway migrations | **Not started** |
| APIs / entities / hash-chain / business logic | **Not started** |
| Tests | **Only the default Spring context-load check** |
| Runnable end-to-end | **Not yet** (the app starts, but has no functional endpoints) |

API examples and test-status badges will be added **only once the corresponding code
exists**. They are intentionally omitted now to avoid implying functionality that has
not been built.

---

## Getting started (local, scaffolding stage)

What genuinely works today: the project compiles, the Spring Boot application starts,
and a local PostgreSQL runs under Docker Compose. There are **no** working endpoints or
migrations yet.

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
docker compose down          # add -v to also delete the data volume
```

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

### Notes
- Secrets are never committed. `application.yml`, `.env.example`, and
  `application-local.yml.example` contain only **local-only** placeholder values;
  real values belong in the git-ignored `.env` / `application-local.yml` or in
  environment variables.
- Dependency versions and how they were verified are recorded in
  [docs/decisions/0001-technology-versions.md](docs/decisions/0001-technology-versions.md).

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
├── ATTESTATION.md                <- authorship attestation (placeholders to be completed)
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
│           └── application-local.yml.example      <- example local override (copy to application-local.yml)
└── docs/
    ├── decisions/
    │   └── 0001-technology-versions.md  <- ADR: verified dependency versions & sources
    ├── requirements/
    │   ├── scenario-a.md          <- assignment requirements vs. our assumptions (A)
    │   ├── scenario-b.md          <- assignment requirements vs. our assumptions (B)
    │   └── scenario-c.md          <- ambiguous requirement clarification (C)
    ├── assumptions.md             <- cross-cutting assumptions & open questions
    ├── ai-usage-log.md            <- honest record of AI use in planning/design
    └── final-engineering-summary.md  <- outline, to be filled in as work proceeds
```

The full approved implementation plan (schemas, hash inputs, redaction scheme, archive
verification, export proof format, authorization matrix, commit sequence) lives outside
this repo in the planning workspace and will be reflected here as `docs/architecture.md`
and ADRs under `docs/decisions/` when implementation begins.

---

## Authorship & AI use

This is individual work. AI assistants were used for planning, drafting, and design
review; the engineer directs the work, reviews every output, and owns correctness and
authorship. See `docs/ai-usage-log.md` for an honest, itemized record of what AI
proposed, what was accepted, modified, or rejected, and why. See `ATTESTATION.md` for
the formal attestation.
