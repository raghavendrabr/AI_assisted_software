# AI Usage Log & Traceability

> **Purpose.** An honest, itemized record of how AI assistance was used on this project:
> what the AI proposed, what the engineer (Raghavendra Begur Rangaramu) accepted,
> modified, or rejected, and why. This log is maintained as work proceeds. It is written
> to *accurately* represent authorship: several core design ideas were **AI-proposed and
> then human-reviewed and corrected** — they are recorded as such, not as purely
> human-originated.
>
> **Sign-off convention.** Each entry ends with a human sign-off line recording that the
> engineer reviewed and approved that entry's AI-assisted work. All entries have been signed
> off (Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18).

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
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

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
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

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
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

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
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

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
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

### AI-006 — Authentication (engineer-driven correction)

- **Issue the engineer raised:** an early sketch trusted a client-supplied role header.
- **Resolution (engineer-directed):** clients send **`X-API-Key` only**; the role is
  resolved **server-side** from a stored key hash. Secrets live in git-ignored config;
  committed config carries placeholders only.
- **Accepted:** server-side key→role mapping; placeholder-only committed config.
- **Rejected:** trusting any client-supplied role.
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

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
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

### AI-008 — This documentation set (AI-drafted, engineer to review)

- **Intent:** Day 1 Step 1 — git init + requirements/assumptions/attestation/AI-log/README/summary outline, no application code.
- **What the AI did:** drafted the files in this commit per the engineer's explicit
  instructions (separate requirements from assumptions; placeholders for personal
  info; honest AI-usage record; README labeled as design-stage with no fake run/test
  claims).
- **Accepted / Modified / Rejected:** Accepted after review — the requirements/assumptions/
  attestation/AI-log/README/summary-outline files were reviewed and committed as the first
  commit; personal-info placeholders were intentionally retained for the engineer to complete.
- **Engineer validation:** the engineer reviewed every file before the first commit was made.
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

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

- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

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
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

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
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

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
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

## Session 5 — Transactional append & write API (Day 1, Commit 5)

### AI-013 — Append pipeline (entities, service, controller, tests)

- **Intent / prompt (from the engineer):** JPA entities + repositories; DTOs + validation;
  transactional append using `SELECT ... FOR UPDATE`; persist the exact microsecond-normalized
  timestamps used for hashing; `POST /api/v1/audit/events`; exception handling; and append,
  rollback, duplicate-ID, and concurrent-append integration tests. No read/verify/security
  (real)/redaction/archival/export.
- **What the AI produced:** `AuditEventEntity`, `AuditChainHeadEntity` (+ `resetToEmpty` for
  test fixtures), `AuditEventRepository`, `AuditChainHeadRepository`
  (`findAndLockSingleton` = PESSIMISTIC_WRITE), `AppendEventRequest`/`AppendEventResponse`
  DTOs with Bean Validation, `AuditEventAppendService` (locked-head transactional append),
  `AuditEventController` (`POST` only), `AuditExceptionHandler` + `ApiError`, `HexFormatUtil`,
  `HashingConfig`/`TimeConfig` beans, a temporary permit-all `SecurityFilterChain`, and
  integration tests. ADR 0004 records the design.
- **Timestamp integrity:** the service normalizes both timestamps to UTC + microseconds and
  uses the SAME values for hashing and persistence (a `Clock` bean is injected for testability).
- **Build findings (honest, in ADR 0004):** Spring Boot 4 removed `TestRestTemplate` (switched
  to `MockMvcTester`) and moved `@AutoConfigureMockMvc` into the dedicated
  `spring-boot-webmvc-test` module (added as a test dependency). Same per-technology module
  split pattern as the earlier Flyway finding.
- **Accepted / Rejected:** accepted head-lock serialization (correctness over throughput,
  documented); accepted a temporary permit-all security config as an explicit boundary until
  the real API-key/role filter. No read/verify/redaction/archival/export added (out of scope).
- **Validation:** full suite **43 tests, 0 failures**, incl. 25-way concurrent append →
  gap-free strictly-increasing linked chain; duplicate id → 409 with no chain advance.
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

## Session 6 — Filtered search & chain verification (Day 1, Commit 6)

### AI-014 — Search + verification (read side of Scenario A)

- **Intent / prompt (from the engineer):** bounded filtered search; deterministic cursor
  pagination; complete chain verification detecting modified fields, modified payload, broken
  previous hash, missing/deleted sequence, malformed stored hash, and inconsistent chain head;
  GET search and verify endpoints; focused integration tests; docs. No redaction/archival/
  export.
- **What the AI produced:** `AuditEventQueryService` (JPA Specification, cursor over
  `sequenceNumber`, `MAX_LIMIT=200` clamp) + `EventSearchCriteria`; `AuditEventSearchController`
  (`GET /api/v1/audit/events`) with `EventView`/`EventPageResponse`; `ChainVerificationService`
  + `ChainViolationType` + `ChainVerificationResult`; `AuditVerifyController`
  (`GET /api/v1/audit/verify`, always 200); repository additions
  (`JpaSpecificationExecutor`, `findAllByOrderBySequenceNumberAsc`). ADR 0005 records it.
- **Verification design:** recomputes each record's content hash from stored fields with the
  same canonical scheme (ADR 0003); reports the first inconsistency in walk order; six
  violation types incl. chain-head consistency. Modified field and modified payload both map to
  `CONTENT_HASH_MISMATCH` (payload is a hashed field) — documented, not a gap.
- **Defense-in-depth finding:** the V1 CHECK constraints block bad-hash-length and
  genesis-with-previous-hash at the storage layer, so those states can't normally be written.
  The verifier still checks them (last line of defense for a tampered restore / a DB without
  CHECKs); tests temporarily drop the CHECK to exercise the verifier, then restore it.
- **Accepted / Rejected:** accepted cursor-over-monotonic-sequence pagination (stable under
  concurrent inserts) over offset; accepted always-200 verify (a broken chain is a valid
  answer, not an HTTP error). No redaction/archival/export added (out of scope).
- **Correctness fixes made in review (engineer-directed):**
  1. Verification now runs `@Transactional(readOnly=true, isolation=REPEATABLE_READ)` so the
     event scan and head read share one snapshot — no false `CHAIN_HEAD_MISMATCH` from a
     concurrent append. Added a concurrent-append-during-verify test.
  2. Cursor pagination switched to **limit + 1**: fetch `limit+1`, return `limit`, set
     `nextCursor` only when the extra row proves another page. Added exact-limit-final-page and
     one-extra-row tests.
  3. Explicit param semantics + validation: `cursor` ⇒ `sequenceNumber > cursor`; always sort
     ascending; `limit <= 0` ⇒ 400; `from` must be strictly before `to` ⇒ else 400; `eventType`
     documented as filtering the stored `action` column.
- **Validation:** full suite **64 tests, 0 failures**; all six required violation types plus
  genesis-link detected at the correct record; pagination stable (limit+1) with correct
  `nextCursor`; concurrent-append verification never false-breaks.
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

## Session 7 — API-key security & compliance reporting (Day 1, Commit 7)

### AI-015 — Server-side API-key auth + compliance access report

- **Intent / prompt (from the engineer):** server-side API-key authentication; WRITER,
  COMPLIANCE_READER, ADMIN roles; endpoint authorization; successful and denied client-account
  access events; compliance access report with actor/account/outcome/time filters; security and
  compliance integration tests; docs.
- **What the AI produced:** `ApiKeyProperties`/`ApiRole`/`ApiKeyService` (SHA-256 + constant-time
  key match, server-side role resolution), `ApiKeyAuthFilter`, `SecurityConfig` (authorization
  matrix, 401 vs 403 handlers, stateless), replacing the temporary permit-all config;
  `ComplianceProperties`/`ComplianceConfig`, `AccessReportEntry`/`AccessReportResponse`,
  `ComplianceReportService`, `ComplianceReportController` (`GET /api/v1/compliance/access-report`);
  an `outcome` filter added to the shared query criteria. ADR 0006 records it.
- **Auth semantics:** client sends only `X-API-Key`; role resolved server-side; no real keys
  committed (`application.yml` uses `${AUDIT_*_KEY:}` placeholders; test keys live in
  `src/test/resources/application.yml` and are clearly non-production). 401 = unauthenticated,
  403 = wrong role.
- **Compliance:** scoped to the configured client-account `resourceType`; includes BOTH
  successful and denied access; filters by actor/account/outcome/time; entries carry
  `sequenceNumber` + `contentHash` for tie-back to the chain; reuses the bounded cursor query.
- **Accepted / Rejected:** accepted static API keys as a documented prototype boundary
  (production → OAuth2/OIDC + mTLS + secret manager); accepted distinct-capability roles with
  ADMIN granted the union explicitly. No redaction/archival/export added (out of scope).
- **Hardening added in review (engineer-directed):** `SecurityConfig` ends with
  `anyRequest().denyAll()` (fail-closed; only the three OpenAPI/Swagger paths are public);
  `ApiKeyService` **fails fast at startup** on a key mapped to multiple roles or a duplicated
  key, treats whitespace-only keys as unset, and never silently picks the first match;
  exceptions/logs never include the key or its digest (principal is the role only). Added
  `ApiKeyServiceValidationTest` and unlisted-endpoint-denied tests.
- **Validation:** full suite **83 tests, 0 failures**; 401/403/2xx enforced per role;
  unlisted endpoint denied; duplicate/multi-role key configs fail fast; success+denied
  client-account reporting with filters; existing tests updated to send keys.
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

## Session 8 — Amendment chain & structured redaction (Day 1, Commit 8)

### AI-016 — Second hash chain + salted-commitment redaction (Scenario B core)

- **Intent / prompt (from the engineer):** the amendment-chain + redaction slice of Scenario B
  (chosen over retention/export for this commit): V2 migration for `audit_amendment`, the
  independently hash-chained amendment log, salted-commitment redaction that nulls plaintext
  without breaking the chain, verifier extended for redaction-backed vs unbacked, and tests.
- **What the AI produced:** V2 migration (`audit_amendment` + amendment tip on the head);
  `AuditAmendmentEntity`/repository; `ProtectedAmendmentProjection` + `canonicalizeAmendment` +
  `amendmentContentHash`; `RedactablePayloadProcessor` (stored envelope vs hash payload);
  `RedactionService` (atomic, head-locked, amendment-backed), `RedactionController`
  (`POST /events/{seq}/redact`, ADMIN); extended `ChainVerificationService` with
  `AMENDMENT_CHAIN_BROKEN`, `REDACTION_UNBACKED`, `COMMITMENT_MISMATCH` and amendment-tip head
  check; `AppendEventRequest.redactableFields`. ADR 0007 records it.
- **Key design:** the content hash commits to a redactable field's `{salt, commitment}` only,
  never the plaintext `value`; so redaction (null the value) leaves `content_hash` unchanged and
  the event chain intact. A null value is legitimate only when a matching REDACTION amendment
  exists. Honest limitation documented: retaining salt+commitment allows offline brute-force of
  low-entropy values — tamper-evidence, not confidentiality-at-rest.
- **Test-isolation fix:** the verification integration test now also clears the amendment table
  in `@BeforeEach` (shared container), and `resetToEmpty` resets both chain tips.
- **Accepted / Rejected:** accepted salted-commitment + amendment backing (per the approved
  plan/ADR); documented crypto-erasure as the deferred production alternative. Retention and
  export deferred to later commits (documented scope boundary).
- **Security hardening confirmed in review (engineer-directed):**
  1. salt is 32 bytes from `SecureRandom` (≥16-byte minimum enforced);
  2. commitment is **domain-separated and bound to eventId + field path**
     (`SHA-256(DOMAIN|eventId|field|salt|value)` with 0x1F separators) — was previously just
     `SHA-256(salt|value)`, which allowed cross-event/field replay; **fixed**;
  3. no plaintext in amendment records or logs (amendment detail is `{field}`+actor only);
  4. **concurrency bug fixed**: the field-state check now happens AFTER acquiring the head lock
     (with a persistence-context clear), so concurrent same-field redaction yields exactly one
     success; previously all N could pass the pre-lock check;
  5. atomic rollback: a failed redaction writes nothing (both chains unchanged).
- **Validation:** full suite **101 tests, 0 failures** (added `RedactablePayloadProcessorTest`
  (6) + 3 integration checks: concurrent-one-succeeds, atomic-rollback, no-plaintext-in-amendment).
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

## Session 9 — Retention & archival (Day 1, Commit 9)

### AI-017 — Archive oldest prefix + merged active/archive verification

- **Intent / prompt (from the engineer):** Flyway V3 (`audit_event_archive` + `archive_manifest`);
  archive only a contiguous oldest prefix; copy before delete; preserve sequence/hashes/payloads/
  timestamps exactly; canonical manifest (manifestId/from/to/count/first/last/archivedAt/
  authorizedBy); ARCHIVE amendment binding the manifest hash+range; atomic copy→manifest→amendment
  →delete; ADMIN-only endpoint; verification reads active+archived as one ordered chain; search/
  compliance include archived (documented includeArchived); redaction works on archived; no
  amendment FK to active-only; detect missing/modified/duplicated archived record + manifest
  mismatches; test rollback + concurrent archive; document retention assumptions/limitations.
  **No signed export in this commit.**
- **What the AI produced:** V3 migration; `AuditEventArchiveEntity`/`ArchiveManifestEntity` + repos;
  `ArchiveManifestHasher` (domain-separated formula); `ArchiveService` (head-locked atomic
  copy→manifest→amendment→delete of the contiguous oldest prefix); `RetentionController`
  (`POST /audit/retention/archive`, ADMIN); verifier rewritten to merge active+archive via a
  source-agnostic `VerifiableEvent` and to check manifests (`ARCHIVE_PROOF_MISMATCH`); search/
  compliance `includeArchived` via a source-agnostic `EventRow`; redaction extended to update the
  archive table. ADR 0008 records it.
- **Design confirmations:** amendment `target_sequence_number` has no physical FK (correct — rows
  move between tables); ARCHIVE amendment binds `{manifestId, manifestHash, from, to, count}`;
  copy strictly before delete; whole operation atomic and head-locked.
- **Accepted / Rejected:** accepted contiguous-oldest-prefix archival (no holes) and manual
  trigger, documented as limitations; deferred scheduled retention, cold storage, and hard
  deletion. Signed export explicitly deferred to Commit 10.
- **Test-isolation:** all event-clearing test resets now also clear archive/manifest/amendment so
  rows don't leak across the shared container (and moved sequences don't collide with a reset head).
- **Manifest encoding hardened:** switched the manifest hash to **length-prefixed** components
  (8-byte big-endian length before each field's UTF-8 bytes) — unambiguous regardless of field
  content, removing the earlier reliance on `authorizedBy` not containing `0x1F`. Documented in
  ADR 0008; unit-tested (`ArchiveManifestHasherTest`).
- **Extra tests added in review:** search across the archive boundary (default excludes archived;
  includeArchived merges once each, ordered; cursor pagination correct across the boundary);
  compliance report includes an archived access exactly once; duplicated sequence across
  active+archive detected; failed archive rolls back leaving active/archive/manifest/amendment and
  both chain-head tips unchanged.
- **Validation:** full suite **117 tests, 0 failures**.
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

## Session 10 — Ed25519-signed bulk export (Day 1, Commit 10)

### AI-018 — Signed export bundle + standalone verifier (completes Scenario B)

- **Intent / prompt (from the engineer):** Ed25519-signed bulk export and standalone bundle
  verification.
- **What the AI produced:** `ExportSigningProperties` + `Ed25519Signer` (private key from an
  env-mounted PEM; ephemeral non-production dev key fallback with a warning); `ExportBundle`
  model; `ExportManifestCanonicalizer` (length-prefixed, server+verifier-shared);
  `ExportService` (builds the signed manifest over active+archive records for a resourceId/
  actorId filter, REPEATABLE_READ); `ExportController` (`GET /audit/export`, COMPLIANCE_READER/
  ADMIN); `ExportBundleVerifier` + `ExportVerifyMain` (standalone, no Spring/DB);
  `scripts/generate-export-keypair.sh`. ADR 0009 records it.
- **Design:** a filtered subset isn't contiguous, so `previous_hash` can't authenticate membership
  and a plain bundle hash is recomputable — hence a detached Ed25519 signature over a canonical
  (length-prefixed) manifest with a dedicated signing key (never the API key). The verifier
  recomputes each event's content hash over the redaction-stable hash payload and checks order +
  count + signature. Honest limitation documented: proves the bundle is unchanged, NOT global
  completeness (needs full chain / Merkle accumulator).
- **Key hygiene:** private key never committed (`.gitignore` blocks `*.pem`, allows
  `*_public.pem`); zero-config demo uses an ephemeral dev key; API key never reused for signing.
- **Verification gaps closed in review (engineer-directed):**
  1. **Amendment verification** — the verifier now recomputes every exported amendment's content
     hash, checks it against the stated hash and `manifest.amendmentHashes` in order, enforces
     ascending amendment sequence + previous-hash linkage for consecutive amendments, and rejects
     modified/reordered/removed/duplicated amendments.
  2. **Redaction consistency** — every null redactable field must be backed by a valid REDACTION
     amendment in the bundle; every present redactable value must match its (eventId+field-bound)
     commitment.
  3. **Filter membership** — every exported event must match the signed filterType/filterValue;
     non-matching injected records are rejected. The endpoint requires exactly one of resourceId/
     actorId (both/neither → 400).
  4. **Event structure** — duplicate event ids/sequences rejected; event order must match the
     signed ordered hash list.
  5. **Key fail-closed** — the ephemeral dev key is allowed ONLY under an explicit local/test
     profile; a deployed/default profile with no private key **fails startup**. Documented that
     the public key must be distributed via a trusted channel and `signingKeyId` alone is not trust.
- **Accepted / Rejected:** accepted Ed25519 signed-manifest over neighbor-witness/bundleHash;
  deferred Merkle completeness proofs and KMS integration (documented).
- **Validation:** full suite **135 tests, 0 failures** (added amendment/redaction/filter/duplicate
  verifier checks + `Ed25519SignerTest` fail-closed + filter-400): signed bundle verifies offline
  incl. archived+redacted; modified/reordered/removed event and amendment, redacted-without-
  amendment, non-matching injected event, duplicate event, tampered manifest, wrong public key all
  rejected; missing production key fails closed; export COMPLIANCE_READER/ADMIN-gated.
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.

---

### AI-019 — Request & security hardening (Commit A of the security/observability pass)

- **Intent:** production-readiness hardening of request handling and HTTP security, scoped to a
  single focused commit. AI drafted an implementation plan; the engineer reviewed it and returned
  13 precise corrections before any code was written (recorded below), then approved implementing
  Commit A only.
- **AI produced:** a streaming `RequestBodySizeLimitFilter` (413; early Content-Length check +
  byte-counting `ServletInputStream` wrapper for chunked/unknown-length bodies, never caching the
  body); Jackson `StreamReadConstraints` (depth 32 / string 64 KiB / number 128) applied via a Boot
  `JsonFactoryBuilderCustomizer` so the request mapper is hardened without replacing Boot's other
  Jackson config; bounded `redactableFields` (count/length/syntax); an `audit.docs.*` property that
  gates springdoc + the security matrix (default off; local public; enabled-private → ADMIN);
  pinned `server.error.*=never`; `Referrer-Policy` + `Permissions-Policy` headers with HSTS
  HTTPS-only and no CSP; explicit CORS deny; a `proxy` profile for forwarded-header trust (off by
  default); and a cross-platform private-key permission check in `Ed25519Signer` (POSIX fail-closed
  outside local/test, non-POSIX documented ACL reliance).
- **Accepted / Modified / Rejected (engineer corrections applied before coding):**
  - Rejected the claim that `server.tomcat.max-http-form-post-size` bounds JSON, and rejected
    `max-swallow-size` as the primary control → replaced with the raw streaming filter.
  - Required stream constraints be applied to the ACTUAL request mapper and NOT replace Boot's
    Jackson config → used `JsonFactoryBuilderCustomizer`.
  - Reclassified public Swagger from P0 to P1 defense-in-depth; required a simple property toggle
    (not competing `SecurityFilterChain` beans).
  - Required forwarded-header trust be profile-gated (not base config) and documented (proxy must
    overwrite inbound headers; direct access restricted).
  - Required the security-header delta be precise (record defaults; add only Referrer-Policy +
    Permissions-Policy; HSTS HTTPS-only; no CSP without live Swagger verification).
  - Required cross-platform key-permission handling (POSIX fail-closed vs warn by profile;
    non-POSIX explicit + documented) and that the key is never logged.
  - Required NO arbitrary Hikari tuning and NO rate-limiting code or disabled placeholder tests in
    this commit — both honored (rate limiting documented as deferred with rationale only).
- **Post-review refactor (engineer-directed):** the POSIX permission-evaluation *decision* was
  extracted into a pure, platform-independent function (`SigningKeyPermissionPolicy.evaluate`) so it
  is unit-testable on every OS. Added 7 cross-platform unit tests (owner-only → safe; group-read,
  group-write, other-read, other-write → unsafe; local/test → warn/allow; non-local → fail-closed).
  The filesystem attribute-view integration test remains conditionally skipped on non-POSIX systems.
- **Engineer validation:** offline `compile`/`test-compile`, then full `./mvnw clean verify` against
  real PostgreSQL (Testcontainers): **167 tests, 0 failures, 3 skipped**. The 25 new tests cover
  413 on declared-length and chunked oversized bodies, at-limit success, depth/string/number → 400,
  error bodies never echoing the payload, redactable count/path/syntax → 400, security headers
  present, HSTS absent over HTTP, forwarded headers untrusted by default, Swagger disabled-by-
  default / public-under-local / ADMIN-only-when-enabled-private, and POSIX key-permission
  fail-closed vs warn. The 3 skips are the POSIX-only key-permission tests, correctly skipped on the
  Windows (NTFS) dev filesystem via a JUnit assumption; they execute on POSIX/CI.
- **Backward compatibility:** additive. API keys, endpoint contracts, and all previously-passing
  tests are unchanged. The only behavioral changes are that the docs surface is no longer public by
  default and oversized/pathological request bodies are now rejected (with generous defaults).
- **Not in this commit (deferred, documented):** OAuth2/OIDC JWT auth, Actuator/metrics/structured
  logging (later commits), and rate limiting (production requirement, deferred with rationale).
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-19.

---

### AI-020 — Conditional dual-mode JWT authentication + API-key auditability (Commit B)

- **Intent:** add an optional OAuth2/OIDC JWT resource server alongside the existing API keys, plus
  non-secret key ids and sanitized auth logging. Engineer specified strict dual-mode/no-fallback
  rules and required tests to use a REAL decoder with locally-signed tokens.
- **AI produced:** `audit.security.jwt.*` properties (enabled/issuer/jwk-set/audiences/algorithms/
  scope-roles) bound to a dedicated namespace (NOT Spring's `issuer-uri`, to avoid triggering the
  auto-configured resource server when disabled); a hardened `NimbusJwtDecoder` (signature +
  algorithm allow-list + issuer + audience + exp/nbf); a strict scope→role converter (trusted scopes
  only, client roles claims ignored, no default role); a `DualCredentialGuardFilter` (both-creds →
  400); an updated `ApiKeyAuthFilter` (never overwrites a JWT auth, no fallback when a Bearer is
  present); key ids on `ApiKeyProperties` with startup validation (safe chars, ≤64, unique); and a
  sanitized `AuthEventLogger` (control-char/CRLF stripping, bounded, never logs secrets).
- **Accepted / Modified / Rejected:**
  - Initial wiring exposed the decoder as an `Optional<JwtDecoder>` bean; this resolved ambiguously
    (Spring wrapped the wrong thing) so **valid tokens were rejected 401**. Fixed by injecting
    `JwtProperties` into `SecurityConfig` and building the decoder inline when complete — caught by
    the real-decoder integration tests, exactly why they were required.
  - Confirmed the Boot 4.1 starter rename: used `spring-boot-starter-security-oauth2-resource-server`
    (the older `-oauth2-resource-server` is deprecated).
  - Verified the Nimbus/Spring-Security 7.1 API surface (StreamReadConstraints-style builder,
    `JwtTimestampValidator` covers exp AND nbf, `JwtClaimValidator` for audience) from the actual
    jars before coding.
- **Engineer validation:** tests exercise the real Bearer filter + real `NimbusJwtDecoder` with a
  local RSA JWK set served over an in-test HTTP endpoint (no external IdP). All required cases pass:
  valid key still works; valid JWT per scope; expired; not-before; malformed; wrong-signature;
  disallowed-algorithm (HS256); wrong-issuer; wrong-audience; missing/insufficient scope (403);
  roles-claim-only (403); unknown scopes grant nothing; both-credentials (400); invalid-Bearer no
  fallback; JWT-disabled + Bearer (401); JWT-disabled + API key works; enabled-but-incomplete fails
  startup; duplicate/invalid key ids fail startup; and no token/key/digest appears in logs or
  responses. Full `./mvnw clean verify` green.
- **Backward compatibility:** additive. API keys and endpoint contracts unchanged; JWT is opt-in. The
  only new client-visible behavior is the JWT path (when enabled), the both-credentials 400, and the
  sanitized auth logs / key-id field.
- **Protocol-check refinements (engineer-directed, before commit):** confirmed and locked with
  focused tests that invalid/expired/malformed/wrong-signature JWTs return 401 **with
  `WWW-Authenticate: Bearer`** (resource-server entry point), insufficient-scope stays **403** (no
  challenge, not downgraded), and API-key/no-credential 401s do **not** advertise Bearer. Changed the
  both-credentials 400 to serialize a real structured `ApiError` (`application/json`, no credential
  echoed). Clarified logging: the raw API-key digest is never logged (principal = non-secret key id),
  and a JWT identity is logged only as a stable **fingerprint** (`jwt:<16 hex>`), never the raw
  subject — added a `JwtAuthEventLoggingFilter` (success side) and fingerprint unit/integration tests.
- **Not in this commit (deferred):** observability/Actuator/metrics (Commit C); mTLS and runtime key
  revocation remain design-only.
- **Human sign-off:** Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-19.

---

## How to read this log going forward

Each future task (implementation, tests, refactors) will get its own `AI-0xx` entry
recording intent, what the AI produced, what was accepted/modified/rejected, engineer
validation performed, and a human sign-off. High-impact changes require an explicit
engineer sign-off before they are relied upon.
