# AI Usage Log & Traceability

> **Purpose.** An honest, itemized record of how AI assistance was used on this project:
> what the AI proposed, what the engineer (Raghavendra Begur Rangaramu) accepted,
> modified, or rejected, and why. This log is maintained as work proceeds. It is written
> to *accurately* represent authorship: several core design ideas were **AI-proposed and
> then human-reviewed and corrected** — they are recorded as such, not as purely
> human-originated.
>
> **Sign-off convention.** Each entry ends with a human sign-off line. Where it reads
> `_<PENDING: Raghavendra to review/approve>_`, the engineer has not yet formally signed
> off. Placeholders are intentional and must be completed by the engineer.

- **AI tools used:** Claude (Anthropic) via an AI coding assistant, for planning,
  drafting documentation, and adversarial design review.
- **Engineer:** Raghavendra Begur Rangaramu — directs the work, reviews every output,
  and owns correctness, maintainability, and authorship.
- **Log status:** Day 1, Step 1 (requirements & design documentation). No application
  code has been generated yet.

---

## Session 1 — Planning & iterative design review (Day 1)

This session produced the approved implementation plan and this initial documentation.
It went through **several rounds of human design review**, in which the engineer rejected
or corrected substantial parts of the AI's initial proposal. The rounds are recorded
below because they are the clearest evidence of engineer-led, AI-accelerated work.

### AI-001 — Initial architecture proposal (AI-generated, human-directed)

- **Intent:** Turn the assignment into an executable plan (stack, data model, hash
  design, scenario breakdown).
- **What the AI proposed:** Java 21 + Spring Boot 3 + PostgreSQL + Flyway; SHA-256 hash
  chain; a locked singleton chain-head row for concurrency; caller `eventTimestamp` +
  server `recordedAt`; cursor pagination; a redaction scheme; a bulk-export bundle; and a
  Scenario C normalization. Much of the overall shape originated from the AI, at the
  engineer's direction.
- **Accepted:** The overall modular-monolith structure, SHA-256 chaining, chain-head
  locking for concurrency, the two-timestamp model, and cursor pagination.
- **Modified / Rejected:** See AI-002…AI-007 below — several specifics were corrected in review.
- **Engineer validation:** Reviewed against the assignment text; directed the
  subsequent correction rounds.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

### AI-002 — Framework version (AI initially wrong; corrected in review)

- **Issue the engineer raised:** the AI initially assumed "Spring Boot 3" and, in a
  later step, proposed springdoc-openapi 2.8.x.
- **What review found:** an official-source check (endoflife.date) showed the Spring Boot
  3.5 line reached open-source EOL on 2026-06-30 and that **4.1** is the current GA line.
  A further check of springdoc release notes showed **2.8.x targets Boot 3.x**, while the
  springdoc **3.1.0** line supports Boot 4.x. Pairing springdoc 2.8.x with Boot 4 would
  be an incompatibility.
- **Accepted:** Pin **Spring Boot 4.1.x** and **springdoc 3.1.x**; re-verify at
  `pom.xml` scaffold time; record in an ADR.
- **Rejected:** the original "Spring Boot 3" + springdoc 2.8.x pairing.
- **Engineer validation:** required version verification against official docs, not memory.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

### AI-003 — Redaction scheme (AI proposal reworked twice in review)

- **What the AI first proposed:** crypto-erasure (encrypt sensitive fields up front,
  hash the ciphertext, destroy the key to redact).
- **First correction (engineer):** for a prototype, prefer a **salted-commitment**
  scheme (store `{salt, commitment}`, null the plaintext on redaction) as simpler and
  defensible; document crypto-erasure as the production alternative.
- **Second correction (engineer, deeper review):** the initial salted-commitment
  description was imprecise about hash coverage. It was corrected so that the canonical
  payload includes **both** `salt` and `commitment` and **excludes only** the mutable
  plaintext `value`; verification must recompute `SHA-256(salt‖value)` when the value is
  present and require a matching intact `REDACTION` amendment when it is null.
- **Honest-limitation requirement (engineer):** the log/docs must state plainly that
  retaining salt+commitment permits offline brute-force of **low-entropy** values — the
  scheme is tamper-evidence, not confidentiality-at-rest. The AI's initial framing
  overstated the privacy guarantee; this was rejected and rewritten.
- **Accepted:** salted-commitment with corrected hash coverage + honest limitation +
  crypto-erasure documented as the production alternative.
- **Rejected:** crypto-erasure as the prototype default; any claim that redacted
  plaintext is unrecoverable.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

### AI-004 — Authorized redaction vs. tampering; immutability & hash coverage of state (engineer-driven correction)

- **Issue the engineer raised:** an early model mutated a single record and left
  `status`/redaction metadata outside integrity protection, so an authorized redaction
  was indistinguishable from tampering.
- **Resolution (engineer-directed):** introduce an **immutable base event + a separate,
  independently hash-chained amendment log**. Redaction/archival are positive, provable,
  append-only facts; a null value is valid only if a matching amendment exists.
- **Terminology correction (engineer):** do **not** claim the whole row is "strictly
  immutable" (a redactable value can go present → null). State precisely that the
  *integrity-protected projection* is immutable and only the hash-excluded `value` may
  transition, via an atomic amendment-backed operation.
- **Accepted:** two-chain design; corrected immutability wording.
- **Rejected:** single-mutable-record model; "strictly immutable row" phrasing.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

### AI-005 — Bulk-export proof (AI proposal rejected and replaced in review)

- **What the AI first proposed:** per-event "neighbor linkage witnesses" plus a
  `bundleHash`, and (in one iteration) using the API key as an HMAC signing key.
- **Issue the engineer raised:** a predecessor hash alone does not authenticate
  membership of a filtered subset; a plain `bundleHash` is recomputable by an attacker
  who edits the bundle; and **an API authentication key must never be reused as a signing
  key**.
- **Resolution (engineer-directed):** a **dedicated Ed25519 export-signing key** signs a
  canonical manifest (export id, timestamp, filters, count, ordered event hashes,
  amendment hashes, chain-head snapshot, signing-key id); ship the public key + a
  standalone verifier; state honestly that this proves the bundle is unchanged since
  export but **not** global completeness without the full chain or a Merkle accumulator.
- **Accepted:** Ed25519 signed-manifest design; dedicated key from env-mounted secret;
  non-production dev keypair clearly labeled if needed for zero-config demos.
- **Rejected:** neighbor-witness/`bundleHash` design; any reuse of the API key for signing.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

### AI-006 — Authentication (engineer-driven correction)

- **Issue the engineer raised:** an early sketch trusted a client-supplied role header.
- **Resolution (engineer-directed):** clients send **`X-API-Key` only**; the role is
  resolved **server-side** from a stored key hash. Secrets live in git-ignored config;
  committed config carries placeholders only.
- **Accepted:** server-side key→role mapping; placeholder-only committed config.
- **Rejected:** trusting any client-supplied role.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

### AI-007 — Amendment reference integrity across archival (engineer-driven correction)

- **Issue the engineer raised:** defining `target_sequence_number` as a physical foreign
  key to `audit_event` alone is wrong, because archival moves rows into
  `audit_event_archive`.
- **Resolution (engineer-directed):** make `target_sequence_number` nullable with **no
  physical FK**; REDACTION requires it (target validated in active ∪ archive), ARCHIVE
  leaves it null and binds the range via canonical detail; add `CHECK` constraints for
  operation-specific required fields; add tests for redacting archived events, invalid
  targets, and archiving already-redacted events.
- **Accepted:** nullable target, no FK, CHECK constraints, added interaction tests.
- **Rejected:** physical FK to `audit_event` only.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

### AI-008 — This documentation set (AI-drafted, engineer to review)

- **Intent:** Day 1 Step 1 — git init + requirements/assumptions/attestation/AI-log/README/summary outline, no application code.
- **What the AI did:** drafted the files in this commit per the engineer's explicit
  instructions (separate requirements from assumptions; placeholders for personal
  info; honest AI-usage record; README labeled as design-stage with no fake run/test
  claims).
- **Accepted / Modified / Rejected:** _<PENDING: to be recorded by Raghavendra after reviewing these files>_
- **Engineer validation:** the engineer will review every file before the first commit is made.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

---

## Session 2 — Project scaffolding & local runtime (Day 1, Step 2)

### AI-009 — Build scaffolding and local PostgreSQL setup

- **Intent / prompt (from the engineer):** Day 1 Step 2 only — scaffold the project and
  local runtime with **no** business functionality. Specifically: rename `master`→`main`;
  verify all framework/dependency versions against **official primary sources** (not
  endoflife.date, not memory) and record them in an ADR; create `pom.xml` with only the
  required dependencies; a minimal entry-point class; `application.yml`,
  `application-local.yml.example`, `docker-compose.yml`, `.env.example`; Postgres-only
  Compose (app via Maven); truthful README; and this log entry. Explicitly **no** tables,
  migrations, entities, repositories, controllers, services, hash logic, or business code.

- **Versions proposed (by AI, then verified):** Spring Boot 4.1.0; Java 21; springdoc
  3.1.0; Flyway, PostgreSQL driver, and Testcontainers left to the Spring Boot BOM.

- **Official sources checked (by direct retrieval, 2026-08-17):**
  - Spring Boot 4.1.0 **system requirements** page (`docs.spring.io/spring-boot/system-requirements.html`): Java 17–26, Maven 3.6.3+, Spring Framework 7.0.8+.
  - **Maven Central `maven-metadata.xml`** (authoritative released-version records) for `spring-boot-starter-parent` (→ 4.1.0), `springdoc-openapi-starter-webmvc-ui` (→ 3.1.0), `flyway-core`/`flyway-database-postgresql`, `postgresql`, `testcontainers/postgresql`, `testcontainers-bom`.
  - **Spring Boot 4.1.0 `spring-boot-dependencies` BOM** read directly for managed versions: Flyway 12.4.0, PostgreSQL driver 42.7.11, Testcontainers 2.0.5 (BOM imports `testcontainers-bom`), Jackson 3.1.4, Spring Framework 7.0.8. springdoc is **not** BOM-managed.

- **Accepted:**
  - Spring Boot 4.1.0 parent; Java 21; **springdoc 3.1.0 pinned** (only non-BOM dependency).
  - **Let the BOM govern** Flyway, PostgreSQL driver, and Testcontainers (declared without versions) — most defensible, avoids drift. Recorded in ADR 0001.
  - Postgres-only Docker Compose with a healthcheck; app run via `mvn spring-boot:run`.

- **Modified (vs. an earlier/naive default):**
  - Did **not** pin standalone-latest Flyway (13.3.0) or PG driver (42.7.13); used the
    BOM-managed 12.4.0 / 42.7.11 instead, to stay within Spring Boot's verified set.
  - Set `spring.jpa.hibernate.ddl-auto=none` and added no migrations, so **no schema is
    created** in this step (honest to the "no tables yet" constraint).

- **Rejected:**
  - endoflife.date and model memory as version sources (used primary metadata instead).
  - Adding an application container to Compose (no genuine image exists yet — Postgres-only).
  - Any secrets in committed files; all sensitive values are env-var placeholders with
    local-only defaults.

- **Validation actually run (2026-08-17, this session):**
  - `mvn compile` — **initially FAILED**, surfacing two real Testcontainers 2.x facts that
    were corrected (recorded in ADR 0001):
    1. the Spring Boot parent does not manage Testcontainers module versions downstream →
       imported `testcontainers-bom` (2.0.5) in `dependencyManagement`;
    2. Testcontainers 2.x **renamed** the module to `org.testcontainers:testcontainers-postgresql`
       (was `org.testcontainers:postgresql` in 1.x) → coordinates fixed. Then compile passed.
  - `mvn dependency:tree` — passed; resolved versions match ADR 0001 exactly (Spring Boot
    4.1.0, PG driver 42.7.11, Flyway 12.4.0, springdoc 3.1.0, Testcontainers 2.0.5).
  - `mvn test` — passed: **1 test, 0 failures** (default context-load smoke test starting a
    real Testcontainers PostgreSQL 16).
  - `docker compose config` — valid.
  - `docker compose up` / health / `down -v` — PostgreSQL reached **healthy** and torn down
    cleanly. Host port 5432 was already taken by an unrelated project's container
    (`converge-data`), which was **left untouched**; validated on `POSTGRES_PORT=5433`
    instead, and added a README note about the override.
  - Toolchain note: Maven was not installed on this machine; a cached Apache Maven 3.9.9
    (from `~/.m2/wrapper/dists`) was used from a scratchpad location to run validation. A
    committed Maven Wrapper is a candidate follow-up so the build is reproducible without a
    global Maven install.
  - **No secrets or private keys** were created or staged; committed config uses only
    local-only placeholders.

- **Engineer validation still pending:** _<Raghavendra to independently review files + re-run
  validation on your machine>_

- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

### AI-010 — Maven Wrapper added to the scaffolding commit

- **Intent / prompt (from the engineer):** add the standard Maven Wrapper to the same
  scaffolding commit, generated with Maven 3.9.9 via the official generator (no
  hand-written or unverified-source scripts), pinned to Apache Maven 3.9.9; update the
  README to use `./mvnw` / `mvnw.cmd`; clarify config-loading semantics; re-validate
  through the wrapper.
- **What the AI did:** ran `mvn wrapper:wrapper -Dmaven=3.9.9` (official
  `maven-wrapper-plugin` 3.3.4) to produce `mvnw`, `mvnw.cmd`, and
  `.mvn/wrapper/maven-wrapper.properties` (`only-script` distribution → no jar).
- **Issue caught during setup:** the Step-1 `.gitignore` ignored
  `.mvn/wrapper/maven-wrapper.properties`; committing that state would have broken the
  wrapper's version pin. Detected via `git check-ignore`; the ignore line was removed so
  the properties file is committed. Recorded in ADR 0001.
- **Accepted:** official-generator wrapper, `only-script`, pinned to 3.9.9 from
  `repo.maven.apache.org`; README switched to `./mvnw` / `mvnw.cmd`; explicit README
  section clarifying that (a) `application-local.yml.example` is a non-loaded template
  until copied to `application-local.yml` **and** the `local` profile is activated (or env
  vars supplied), and (b) Docker Compose `.env` configures Compose only and is not
  auto-exported to a separately launched Maven/JVM process.
- **Rejected:** hand-authored wrapper scripts; downloading the wrapper from any
  unverified source; committing the wrapper properties as ignored.
- **Validation run via the wrapper (2026-08-17):**
  - `./mvnw --version` → Apache Maven **3.9.9** on Java 21 (wrapper downloaded Maven from
    `repo.maven.apache.org` on first use).
  - `./mvnw dependency:tree` → passed; same resolved versions as before (Spring Boot 4.1.0,
    PG 42.7.11, Flyway 12.4.0, springdoc 3.1.0, Testcontainers 2.0.5).
  - `./mvnw test` → passed: **1 test, 0 failures** (context-load smoke test on Testcontainers
    PostgreSQL 16).
  - `docker compose config` → valid; secret/artifact scan → clean; wrapper files staged,
    `target/` ignored.
- **Engineer validation still pending:** _<Raghavendra to re-run `./mvnw`/`mvnw.cmd` on your machine>_
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

## Session 3 — Audit chain schema (Day 1, Commit 3)

### AI-011 — Flyway V1 audit-chain foundation

- **Intent / prompt (from the engineer):** create `V1__create_audit_chain_foundation.sql`
  with exactly two tables (`audit_event`, `audit_chain_head`), the specified columns and
  constraints (32-byte SHA-256 hashes; genesis has null previous_hash; later events require
  a 32-byte previous_hash; unique event id & sequence; non-unique content_hash; positive
  sequence & schema version), a seeded singleton empty-chain head row, three justified
  indexes, a focused Testcontainers schema test, ADR 0002, and specific config-doc
  corrections — with **no** entities/repositories/DTOs/hashing/services/controllers/
  verification/security/redaction/archival/export.
- **What the AI produced:** the V1 migration, `AuditChainSchemaV1Test` (JDBC-level, so it
  tests DB constraints directly without introducing entities/repositories), ADR 0002, and
  the doc corrections.
- **Design choices made explicit (accepted):** BYTEA (raw 32-byte) hashes with
  `octet_length = 32` CHECKs; content_hash intentionally NOT unique; singleton head pinned
  via `CHECK (id = 1)`; empty-chain consistency CHECK; three indexes matching only the
  Scenario-A query patterns; DB-layer CHECKs as deliberate defense-in-depth so direct
  data-store tampering is still rejected.
- **Config-documentation corrections applied (previously approved):**
  - Flyway is **no longer described as inert** — as of V1 it applies a real migration.
  - Clarified `application-local.yml` is **local-only**; non-local secrets use protected
    environment injection or a secret manager, never committed.
  - Documented that `POSTGRES_*` init applies only to a **new, empty** volume.
  - Documented `docker compose down` **preserves** the data volume; `down -v` **deletes** it.
- **Test isolation decision:** `@Transactional` on the schema test so each method rolls back,
  preventing cross-test contamination (e.g. duplicate sequence 1).
- **Rejected / not done:** any entities, repositories, DTOs, hashing, services, controllers,
  search, verification, security, redaction, archival, or export — out of scope for this commit.
- **Build finding (honest):** the schema test initially failed —
  `relation "flyway_schema_history" does not exist`. Root cause: **Spring Boot 4.x moved
  Flyway auto-configuration into a dedicated `spring-boot-flyway` module**; with only
  `flyway-core` present, Flyway never ran. Fixed by adding `spring-boot-flyway`
  (BOM-managed). Recorded in ADR 0002.
- **Validation run (2026-08-18):**
  - `./mvnw test` → **12 tests, 0 failures** (1 context-load + 11 schema tests); Flyway
    applied V1 in-test.
  - `docker compose config` → valid.
  - Applied V1 at app startup against Compose PostgreSQL 16 (port 5433, since 5432 was held
    by an unrelated project); Flyway created `flyway_schema_history` and applied V1.
  - DB inspection: `flyway_schema_history` shows V1 success=t; `audit_event` +
    `audit_chain_head` exist; singleton seed row `id=1, current_sequence=0, current_hash=NULL`;
    `audit_event` empty; all 7 audit_event and 5 chain_head constraints + 3 indexes present;
    a bad-hash-length insert was rejected by `ck_audit_event_content_hash_len`.
  - Torn down with `down -v`; `git diff --check` clean; no secrets/artifacts staged.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

## Session 4 — Canonical serialization & hashing (Day 1, Commit 4)

### AI-012 — Deterministic canonical JSON + SHA-256 content hashing

- **Intent / prompt (from the engineer):** implement deterministic canonical JSON
  serialization, an explicitly documented protected hash projection, and SHA-256 hashing,
  with unit tests proving determinism, field-order independence, payload-key-order
  independence, UTF-8 behavior, null handling, timestamp normalization, and that changing
  any protected field changes the hash. **No** entities/repositories/APIs/DB
  writes/search/verification/security/redaction/archival/export.
- **What the AI produced:** `ProtectedEventProjection` (the explicit protected field set),
  `CanonicalJsonSerializer` (own deterministic writer; Jackson used only to parse the
  payload tree), `Sha256Hasher` (content hash + genesis-hash constant), and
  `CanonicalHashTest` (16 unit tests). ADR 0003 records the exact projection,
  canonicalization rules, and hash formula.
- **Exact formula recorded (ADR 0003):**
  `content_hash = SHA-256(UTF-8(canonicalize(projection)))`.
  Canonicalization: fixed non-alphabetical top-level order; payload object keys sorted by
  `String.compareTo` recursively (array order preserved); UTF-8; explicit `null` token;
  timestamps → UTC **truncated to microseconds**, formatted `uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'`
  (6 digits); `previousHash` rendered as **64 lowercase hex chars** (null for genesis); no
  insignificant whitespace; numbers via `BigDecimal.stripTrailingZeros().toPlainString()`.
- **Jackson-3 note:** Spring Boot 4.1 ships Jackson 3.x whose base package is
  `tools.jackson.*` (not `com.fasterxml.jackson.*`); the serializer imports accordingly.

- **Integrity corrections made in review (engineer-directed):**
  1. **Removed the `SHA-256("AUDIT_LOG_GENESIS_V1")` genesis-hash convention** — it
     contradicted the already-migrated V1 schema. The approved convention (empty head =
     seq 0/null; first event = seq 1/`previousHash` null → `"previousHash":null`; later
     events carry the previous 32-byte content hash) is now enforced in
     `ProtectedEventProjection` and documented in ADR 0003. `genesisPreviousHash()`/
     `GENESIS_LABEL` deleted from `Sha256Hasher`.
  2. **Timestamp precision made PostgreSQL-safe** — was nanosecond (`.nnnnnnnnn`); now UTC +
     **truncate to microseconds** + `.SSSSSS` (6 digits), so the canonical form is unchanged
     after a `TIMESTAMPTZ` persist/reread. Documented that the append service must persist the
     same microsecond-truncated instant it hashed.
  3. **`previousHash` encoding made explicit** — projection now holds `byte[]` (32 bytes,
     validated); the serializer renders exactly 64 lowercase hex chars; null stays the JSON
     null token. Encoding owned solely by the serializer.
- **Added tests (now 21):** equal offsets canonicalize identically; sub-microsecond
  differences collapse to the same hash; a 1-µs difference changes the hash; persist/reread
  round-trip is stable; `previousHash` = 64 lowercase hex; genesis = null token.
- **Accepted / Rejected:** accepted a bespoke canonical writer over ObjectMapper default
  ordering; documented UTF-16 code-unit key ordering as a `schemaVersion`-gated limitation.
  Rejected the genesis-hash sentinel and nanosecond timestamp precision. No storage/API/
  security code added (out of scope).
- **Validation:** `./mvnw test -Dtest=CanonicalHashTest` → **21 tests, 0 failures**; full
  suite result recorded below.
- **Human sign-off:** _<PENDING: Raghavendra to review/approve>_

---

## How to read this log going forward

Each future task (implementation, tests, refactors) will get its own `AI-0xx` entry
recording intent, what the AI produced, what was accepted/modified/rejected, engineer
validation performed, and a human sign-off. High-impact changes require an explicit
engineer sign-off before they are relied upon.
