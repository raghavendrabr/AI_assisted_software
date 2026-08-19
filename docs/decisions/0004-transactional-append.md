# ADR 0004 — Transactional Append & Write API

- **Status:** Accepted (pending engineer sign-off)
- **Date:** 2026-08-18
- **Context:** Implement the write path: JPA entities/repositories, request/response DTOs with
  validation, a transactional append that serializes on the chain head, the
  `POST /api/v1/audit/events` endpoint, and exception handling. No read/query, verify,
  security (real), redaction, archival, or export yet.

## eventId & duplicate handling (semantics)

- **`eventId` is server-generated** (random UUID per request). The request body has no
  `eventId` field; clients cannot supply or reuse one.
- **`POST` is NOT idempotent.** A retried request creates a new event. Client-controlled
  idempotency keys are deferred and would be added explicitly if needed.
- **The UNIQUE constraint on `event_id` is authoritative.** The service's `existsByEventId`
  pre-check is only an *early defensive check* — it turns the common case into a clean 409
  without a failed DB round-trip, but it does **not** close the check-then-insert race by
  itself. A concurrent insert of the same id is caught by the DB unique constraint, raised as
  `DataIntegrityViolationException`, and translated to **409** by the exception handler — never
  an undocumented 500. This protects against an extremely unlikely generated-UUID collision or
  internal duplicate, not a normal client retry.

## Append algorithm (single transaction)

1. Early defensive duplicate `eventId` pre-check (`existsByEventId`) → 409. (The DB unique
   constraint remains the authoritative guard; see above.)
2. **Lock** the singleton `audit_chain_head` row with `SELECT ... FOR UPDATE`
   (`@Lock(PESSIMISTIC_WRITE)`), serializing all concurrent appends.
3. Compute `sequenceNumber = head.currentSequence + 1`; `previousHash = head.currentHash`
   (null when the chain is empty → genesis).
4. **Normalize timestamps**: `recordedAt = now()` and (caller-supplied or defaulted)
   `eventTimestamp`, both converted to UTC and **truncated to microseconds**. The SAME
   normalized values are hashed AND persisted (ADR 0003), so the stored row re-verifies after
   a reread.
5. Build the `ProtectedEventProjection`, compute `contentHash = SHA-256(canonical)`.
6. `INSERT` the event; **advance** the locked head to `(sequenceNumber, contentHash)`.
7. Commit. Any failure rolls the whole thing back — no partial event, no head advance.

**Concurrency guarantee (tested):** with the head lock, N concurrent appends produce a
gap-free, strictly-increasing sequence `1..N`, each record's `previousHash` equal to the
prior record's `contentHash`. Verified by `AuditEventAppendServiceTest` (25 parallel appends).

## Server-assigned vs caller-supplied

- **Caller supplies:** `eventType`→action, `actorId`, `actorType`, `resourceType`,
  `resourceId`, `outcome`, optional `businessReason`, optional `payload`, optional
  `eventTimestamp` (business time).
- **Server assigns (never trusted from caller):** `eventId` (random UUID), `sequenceNumber`,
  `recordedAt`, `previousHash`, `contentHash`, `schemaVersion`.

## API

- `POST /api/v1/audit/events` → `201 Created`, `Location` header, body echoing id/sequence/
  timestamps/hashes (hashes as lowercase hex). **Append-only:** no update/delete endpoints.
- Errors (`@RestControllerAdvice`): validation → `400` with field details; malformed JSON →
  `400`; duplicate id → `409` (from BOTH the pre-check `DuplicateEventIdException` AND the
  authoritative `DataIntegrityViolationException`); structured `ApiError` body.

## Temporary security posture

`spring-boot-starter-security` is on the classpath; until the real API-key/role filter is
built (a later step), a **temporary permit-all** `SecurityFilterChain` disables the default
Basic-auth wall and CSRF so the write API is exercisable. This grants no authorization and is
documented as an explicit, temporary boundary to be replaced.

## Build findings — Spring Boot 4 test-module split

Two Boot-4 module relocations were discovered during validation and are recorded for defense:

1. **`TestRestTemplate` was removed** from the Boot test jars. We use **`MockMvcTester`**
   (from `spring-test` 7.x) instead for HTTP-level tests.
2. **`@AutoConfigureMockMvc` / MockMvc test slice moved** into the dedicated
   **`spring-boot-webmvc-test`** module (package
   `org.springframework.boot.webmvc.test.autoconfigure`). Added as a test dependency
   (BOM-managed). This mirrors the earlier Flyway auto-config split (ADR 0002) — Boot 4
   decomposed the monolithic autoconfigure/test jars into per-technology modules.

## Trade-offs

- **Head-lock serialization** caps write throughput by design (one append at a time). This is
  the honest cost of a single deterministic tamper-evident chain; horizontal approaches
  (sharded chains) are documented future work, not built.
- **Payload storage**: the request payload is stored as its JSON text in a `jsonb` column and
  hashed via the canonical serializer (keys sorted). The stored `jsonb` and the canonical
  hash input are independent representations; verification always recomputes from fields.

## Validation

`AuditEventAppendIntegrationTest` (HTTP, MockMvcTester): 201 genesis (null previousHash,
64-hex contentHash), second event links to first, microsecond-normalized timestamp persisted,
missing-field → 400 (nothing persisted), malformed JSON → 400, no update/delete endpoint.
`AuditEventAppendServiceTest` (service): linked chain, duplicate id → 409 with no chain
advance (rollback), 25 concurrent appends → gap-free strictly-increasing linked chain.

## Engineer sign-off
_<PENDING: Raghavendra to review/approve the append design and API>_
