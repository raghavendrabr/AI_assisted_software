# ADR 0002 — Audit Chain Schema (V1)

- **Status:** Accepted (pending engineer sign-off)
- **Date:** 2026-08-18
- **Context:** First schema migration (`V1__create_audit_chain_foundation.sql`). Defines the
  two foundational tables — `audit_event` (append-only, hash-chained records) and
  `audit_chain_head` (singleton chain tip) — with the integrity constraints that make
  tampering detectable at the database layer. No application code, hashing, or business
  logic is introduced here.

## Decisions

### Keys & identity
- **Surrogate PK `id BIGINT GENERATED ALWAYS AS IDENTITY`** on `audit_event`, kept
  distinct from both the public id and the chain ordering key. Storage internals are never
  overloaded with business meaning.
- **`event_id UUID` unique** — the opaque, externally-visible identifier.
- **`sequence_number BIGINT` unique, `> 0`** — the monotonic chain position. Genesis = 1.
  The chain is ordered by this column; uniqueness prevents two records occupying one slot.

### Hash columns (BYTEA, SHA-256)
- `previous_hash BYTEA` and `content_hash BYTEA NOT NULL`, stored as raw bytes (not hex)
  to be compact and unambiguous.
- **Exactly 32 bytes** enforced via `octet_length(...) = 32` CHECKs (SHA-256 = 256 bits).
  `content_hash` is always 32 bytes; `previous_hash` is either NULL (genesis) or 32 bytes.
- **`content_hash` is intentionally NOT unique.** Two records could legitimately hash the
  same field-content at different positions; record uniqueness is guaranteed by
  `sequence_number` and the chain linkage, not by content-hash uniqueness. Making it unique
  would wrongly reject valid duplicate-content events.

### Chain linkage rule
- `ck_audit_event_genesis_prev_hash`:
  `sequence_number = 1 ⇒ previous_hash IS NULL`; `sequence_number > 1 ⇒ previous_hash IS NOT NULL`.
  Together with the 32-byte length CHECK, this makes the genesis-vs-linked distinction a
  hard database invariant.

### Other value constraints
- `schema_version INTEGER NOT NULL DEFAULT 1`, CHECK `> 0` — versions the canonical
  hashing/serialization scheme so the verifier can evolve without ambiguity.
- Timestamps: `event_timestamp` (caller-supplied business time) and `recorded_at`
  (server ingestion time, DB-defaulted to `now()` as a safety net; the app will set it).
- `payload JSONB NOT NULL DEFAULT '{}'` — structured, queryable event detail.
- `outcome`, `actor_type`, `business_reason` (optional) support the compliance/report
  needs of later scenarios without over-modeling now.

### Singleton `audit_chain_head`
- **Singleton enforced by `PRIMARY KEY (id)` pinned via `CHECK (id = 1)`** — at most one
  row can ever exist.
- Seeded with exactly one **empty-chain** row: `current_sequence = 0`, `current_hash = NULL`.
- `ck_audit_chain_head_empty_consistency`:
  `current_sequence = 0 ⇔ current_hash IS NULL`; `current_sequence > 0 ⇒ 32-byte current_hash`.
- `current_sequence >= 0`; `current_hash` NULL-or-32-bytes.
- **Concurrency note (implemented later):** the append service will `SELECT ... FOR UPDATE`
  this row inside the append transaction to serialize writes and keep one deterministic
  chain. Documented in the table/column comments; no locking logic exists yet.

### Indexes (only the justified ones)
Chosen to serve exactly the Scenario-A query patterns (filter + time range); nothing
speculative:
- `ix_audit_event_event_timestamp (event_timestamp)` — time-range queries.
- `ix_audit_event_actor_time (actor_id, event_timestamp)` — actor filter over time.
- `ix_audit_event_resource_time (resource_type, resource_id, event_timestamp)` — resource
  filter over time.
No index on `content_hash`/`previous_hash` (verification walks by `sequence_number`, which
is already uniquely indexed; hashes are not query dimensions).

## Trade-offs / notes
- DB-layer CHECKs duplicate some rules the application will also enforce. This is deliberate
  defense-in-depth: the whole point is that tampering *directly in the data store* is still
  caught, so the DB must independently reject structurally-invalid records.
- BYTEA vs hex TEXT: BYTEA is chosen for compactness and to avoid encoding ambiguity.
- The genesis/linked CHECK assumes a single global chain (per ADR 0001 / assumptions).
  Per-tenant chaining would revisit the sequence/linkage constraints.

## Build finding — Spring Boot 4 moved Flyway auto-configuration

During validation the schema test failed with `relation "flyway_schema_history" does not
exist` — Flyway never ran at startup despite `flyway-core` being on the classpath and
`spring.flyway.enabled=true`. Root cause: **Spring Boot 4.x extracted Flyway
auto-configuration into a dedicated `org.springframework.boot:spring-boot-flyway` module**
(it is no longer in `spring-boot-autoconfigure`). Fix: add `spring-boot-flyway`
(BOM-managed, 4.1.0) as a dependency. Verified by inspecting the module jar
(`FlywayAutoConfiguration` present) and confirming the version is BOM-governed. Recorded
here rather than hidden because it is a genuine Boot-4 migration gotcha worth defending.

## Validation
Covered by `AuditChainSchemaV1Test` (Testcontainers PostgreSQL 16): Flyway V1 applies,
both tables + singleton seed row exist, valid genesis and later events insert, and invalid
sequence, invalid hash length, invalid previous-hash rule, duplicate event id, and
duplicate sequence number are all rejected.

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.
