# Architecture Overview — Tamper-Evident Audit Log Service

## 1. Purpose & scope

A service that records an **append-only** history of events and makes any modification or
deletion of past records **detectable** via cryptographic hash chains. It implements the three
assignment scenarios:

- **Scenario A** — core audit log: write, filtered/paginated query, and full chain verification.
- **Scenario B** — retention/archival, structured redaction, and a signed, independently
  verifiable bulk export.
- **Scenario C** — a clarified compliance-reporting requirement + implemented access-report slice.

## 2. Stack & rationale

| Concern | Choice | Why |
|---|---|---|
| Language/runtime | Java 21 | Supported LTS; matches an enterprise target. |
| Framework | Spring Boot 4.1 | Current stable GA (3.5 reached OSS EOL 2026-06-30). See ADR 0001. |
| Persistence | PostgreSQL 16 + Spring Data JPA, Flyway | Real `SELECT ... FOR UPDATE`, JSONB, versioned schema. |
| Hashing | SHA-256 over a canonical serialization | Deterministic, standard, defensible (ADR 0003). |
| Export signing | Ed25519 (dedicated key) | Authenticates a filtered subset a plain hash cannot (ADR 0009). |
| Build/tests | Maven Wrapper, JUnit 5, Testcontainers | Reproducible build; high-fidelity integration tests on real PostgreSQL. |

Deliberately a **modular monolith** — no Kafka/Redis/microservices — to finish, test, and defend
within the time box. Dependency versions are BOM-governed (only springdoc and Testcontainers are
pinned explicitly); all versions were verified against primary sources (ADR 0001).

## 3. Module layout

```
com.raghavendra.audit
├── event/        write + query: entities, repositories, append service, controllers, DTOs
├── amendment/    the second (lifecycle) hash chain: redaction/archive amendment records
├── redaction/    salted-commitment redaction (RedactablePayloadProcessor, RedactionService)
├── retention/    archival (ArchiveService, manifest hashing, archive entities)
├── verify/       chain verification (events + amendments + archive manifests)
├── export/       Ed25519-signed bulk export + standalone verifier
├── compliance/   compliance access report (Scenario C slice)
└── common/       canonical serializer, Sha256Hasher, hex util, security (API key), time/clock
```

## 4. Data model

- **`audit_event`** — append-only base records. Integrity-relevant projection is immutable; the
  only permitted mutation is nulling a *declared-redactable* field's plaintext `value` (which the
  content hash never covered). Columns: `sequence_number` (monotonic chain position),
  `event_id` (public UUID), actor/resource/action/outcome/business_reason, `event_timestamp`
  (business time) + `recorded_at` (ingestion time), `payload` (JSONB), `previous_hash`,
  `content_hash` (both BYTEA, 32-byte SHA-256).
- **`audit_amendment`** — a **second, independently hash-chained** log of lifecycle changes
  (REDACTION, ARCHIVE). Makes an authorized redaction/archival a *positive, provable* fact rather
  than an indistinguishable mutation.
- **`audit_chain_head`** — singleton row tracking both chain tips; locked `FOR UPDATE` on every
  append/amendment to serialize writes into one deterministic chain.
- **`audit_event_archive`** + **`archive_manifest`** — archived (moved) events and the manifest
  binding each archival operation's range under a `manifest_hash`.

### Two-chain design (key decision)

The naive "mutate the record" approach cannot distinguish an authorized redaction from tampering
and leaves lifecycle state outside integrity protection. Instead, **base events are immutable**
(save the hash-excluded redactable value) and **lifecycle changes are separate hash-chained
amendments**. Verification then has two invariants: every base event's `content_hash` recomputes,
and every deviation (a null redactable value, an archived range) is explained by an intact
amendment. See ADR 0002/0007/0008.

## 5. Hashing & chain design

- **Canonical serialization** (ADR 0003): fixed field order, recursively sorted payload keys, UTF-8,
  explicit nulls, **timestamps normalized to UTC + microseconds** (matching PostgreSQL
  `TIMESTAMPTZ`, so a persist/reread round-trip doesn't change the hash), `previous_hash` rendered
  as 64-char lowercase hex, numbers via `BigDecimal.stripTrailingZeros().toPlainString()`.
- `content_hash = SHA-256(UTF-8(canonical projection))` — 32 bytes.
- **Genesis convention (no sentinel):** empty head = sequence 0/null; first event = sequence 1 with
  `previous_hash = null`; later events carry the prior record's 32-byte content hash. The amendment
  chain mirrors this.
- **Redaction commitment (ADR 0007):** each redactable field stores `{salt, commitment, value}`;
  the hash commits to `{salt, commitment}` only. `commitment = SHA-256(DOMAIN | eventId | field |
  salt | value)` — domain-separated and bound to event id + field path (no cross-event/field
  replay), 32-byte SecureRandom salt.

## 6. API design

Base path `/api/v1`. All endpoints require authentication — an `X-API-Key` (role resolved
server-side) or, when JWT mode is enabled, an OAuth2/OIDC `Bearer` token whose trusted scopes map to
the same roles (ADR 0011). Supplying both is rejected with 400.

| Endpoint | Method | Role | Purpose |
|---|---|---|---|
| `/audit/events` | POST | WRITER, ADMIN | Append an event (server assigns id/sequence/timestamps/hashes) |
| `/audit/events` | GET | COMPLIANCE_READER, ADMIN | Filtered, cursor-paginated search (`includeArchived`) |
| `/audit/verify` | GET | COMPLIANCE_READER, ADMIN | Walk both chains + manifests; report first inconsistency |
| `/audit/events/{seq}/redact` | POST | ADMIN | Salted-commitment redaction (amendment-backed) |
| `/audit/retention/archive` | POST | ADMIN | Archive the oldest contiguous prefix older than a cutoff |
| `/audit/export` | GET | COMPLIANCE_READER, ADMIN | Ed25519-signed, independently verifiable bundle |
| `/compliance/access-report` | GET | COMPLIANCE_READER, ADMIN | Client-account access report (Scenario C) |

**Append-only:** no update/delete endpoints exist. **Fail-closed authz:** the security chain ends
with `denyAll()`, so a new endpoint is denied until an explicit rule grants it.

## 7. Concurrency & correctness

- Every append/amendment/archival serializes on the singleton head row (`SELECT ... FOR UPDATE`) →
  one gap-free, strictly-increasing chain with correct `previous_hash` linkage (tested with 25
  concurrent appends).
- Redaction acquires the head lock **before** re-reading the field state (persistence context
  cleared), so concurrent same-field redactions yield exactly one success.
- Verification runs `REPEATABLE_READ` so the event scan and head read see one coherent snapshot
  (no false `CHAIN_HEAD_MISMATCH` under concurrent appends).

## 8. Security posture

- **Authentication (dual-mode):** `X-API-Key` → role resolved server-side (SHA-256 + constant-time
  compare); client never supplies a role. Optional OAuth2/OIDC **JWT** mode (`audit.security.jwt.*`,
  off by default) validates signature + algorithm allow-list + issuer + audience + exp/nbf, and maps
  only trusted scopes (`audit.write|read|admin`) to roles — client `roles`/`authorities` claims are
  ignored, no default role (ADR 0011). Both filters feed the **same** authorization matrix and
  `denyAll()`. Dual-credential requests → 400; an invalid Bearer never falls back to an API key.
  401 = unauthenticated, 403 = wrong role/scope.
- **Conditional activation & fail-fast:** JWT enabled-but-incomplete fails startup; API-key config
  fails fast on duplicate/multi-role keys and duplicate/invalid key ids. No real keys committed
  (env placeholders).
- **Auditability:** each API key has a stable, non-secret **key id**; sanitized auth logs record
  method/result/reason/requestId + key id or JWT-subject fingerprint — never the key, token, or a
  digest. Key rotation/revocation is a config update + restart/reload (no runtime revocation).
- **Export signing:** dedicated Ed25519 key from a mounted secret; ephemeral dev key only under
  local/test profile, else fail-closed. Public key distributed out of band (trust note in ADR 0009).
- **Request hardening (ADR 0010):** streaming body-size cap (413), Jackson stream constraints (400),
  security headers, docs gated by `audit.docs.*`, forwarded headers trusted only under the `proxy`
  profile.
- **Prototype boundary:** mTLS and runtime key revocation are not implemented (documented future
  work).

## 9. Verification behaviors (violation types)

`GET /audit/verify` walks active∪archived events (one ordered stream) + the amendment chain +
manifests, reporting the first inconsistency: `CONTENT_HASH_MISMATCH` (modified field/payload),
`PREVIOUS_HASH_MISMATCH`, `SEQUENCE_GAP`, `MALFORMED_STORED_HASH`, `GENESIS_LINK_VIOLATION`,
`CHAIN_HEAD_MISMATCH`, `AMENDMENT_CHAIN_BROKEN`, `REDACTION_UNBACKED`, `COMMITMENT_MISMATCH`,
`ARCHIVE_PROOF_MISMATCH`. Always HTTP 200 (a broken chain is a valid answer in the body).

## 10. Key trade-offs (see ADRs for full detail)

- **Throughput vs. determinism:** the head lock serializes writes — honest for a single
  tamper-evident chain; sharded chains are future work.
- **Redaction privacy:** salted commitment is tamper-evidence, **not** confidentiality-at-rest
  (low-entropy values are brute-forceable); crypto-erasure is the production alternative.
- **Export completeness:** the signed bundle proves the exported set is unchanged, **not** global
  completeness (needs the full chain or a Merkle accumulator).
- **Retention:** manual trigger, contiguous-oldest-prefix, moved-not-destroyed.

Decision records: `docs/decisions/0001`–`0009`.
