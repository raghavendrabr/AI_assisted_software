# ADR 0005 — Filtered Search & Chain Verification

- **Status:** Accepted (pending engineer sign-off)
- **Date:** 2026-08-18
- **Context:** Implement the read side — a bounded, filtered, cursor-paginated search over
  events, and full chain verification that detects tampering. Completes Scenario A's
  query + verify requirements. No redaction/archival/export/real-security yet.

## Search API — `GET /api/v1/audit/events`

- **Filters (all optional, combined with AND):** `actorId`, `resourceType`, `resourceId`,
  `eventType`, `from`/`to`. **`eventType` filters the stored `action` column** (the write API
  accepts `eventType` and persists it as `action`; documented so the mapping is explicit).
  `from` is inclusive, `to` exclusive.
- **Time range validation:** if both `from` and `to` are present, `from` must be **strictly
  before** `to`; otherwise `400`.
- **Ordering:** always `sequenceNumber` ascending — a monotonic, insert-stable key.
- **Cursor pagination (limit + 1):** `cursor` means `sequenceNumber > cursor`. The query fetches
  at most `limit + 1` rows, returns at most `limit`, and sets `nextCursor` (the last returned
  event's sequence) **only when the extra row proves another page exists**. This avoids a
  dangling cursor on an exact-limit final page. Cursor-over-a-monotonic-column is stable under
  concurrent inserts (offset pagination would shift).
- **Bounded & validated:** an explicit `limit <= 0` is rejected with `400` (not silently
  normalized); an omitted `limit` defaults to 50; values above `MAX_LIMIT = 200` are clamped,
  and the response `limit` reflects the applied value. JPA `Specification` +
  `PageRequest(0, limit + 1, sort ASC)`.

## Verification API — `GET /api/v1/audit/verify`

Walks the chain in `sequenceNumber` order, recomputing each record's content hash from its
stored fields using the exact canonical scheme (ADR 0003), and reports the FIRST inconsistency.
Always returns **HTTP 200** — a broken chain is a valid answer (the assignment validates by
tampering then re-verifying), not an HTTP error; callers read `intact` in the body.

**Isolation:** verification runs in
`@Transactional(readOnly = true, isolation = REPEATABLE_READ)`. The event scan and the
chain-head read must observe ONE consistent snapshot; otherwise a concurrent append committing
between them could make the head look ahead of the scanned events and produce a **false**
`CHAIN_HEAD_MISMATCH`. Under PostgreSQL REPEATABLE_READ (snapshot isolation), both reads see the
same point-in-time chain. Verified by `verificationRemainsConsistent_whileAppendsOccurConcurrently`
(verify repeatedly while a second thread appends continuously — never a false break).

### Detected violation types (first wins, in walk order)

| Violation | Trigger |
|---|---|
| `SEQUENCE_GAP` | a sequence number is missing/deleted (walk expects 1,2,3,…) |
| `MALFORMED_STORED_HASH` | a stored `content_hash`/`previous_hash` is not 32 bytes |
| `GENESIS_LINK_VIOLATION` | genesis has a `previous_hash`, or a later record lacks one |
| `PREVIOUS_HASH_MISMATCH` | a record's `previous_hash` ≠ the prior record's `content_hash` (reorder/relink) |
| `CONTENT_HASH_MISMATCH` | recomputed content hash ≠ stored — a **modified field OR modified payload** |
| `CHAIN_HEAD_MISMATCH` | the `audit_chain_head` row disagrees with the actual tip (sequence or hash) |

Note: "modified field" and "modified payload" both surface as `CONTENT_HASH_MISMATCH`, because
the payload is one of the hashed fields — this is by design, not a gap. An attacker who edits a
field *and* recomputes that record's own content hash still breaks the NEXT record's
`previous_hash` linkage (`PREVIOUS_HASH_MISMATCH`), so the chain remains tamper-evident.

## Defense-in-depth interaction with V1 CHECK constraints

Some malformed states (bad hash length, genesis with a previous_hash) are **also** blocked by
the V1 CHECK constraints at the storage layer — so they cannot normally be written. The
verifier still checks them independently because it is the last line of defense if such data
arrives another way (a restore from a tampered dump, logical replication, or a database without
the CHECKs). The corresponding tests temporarily drop the relevant CHECK to exercise the
verifier's own logic, then restore it so DDL never leaks across tests.

## Validation

- `AuditEventSearchIntegrationTest`: filter-by-actor, combined resource+eventType AND,
  cursor pagination (stable, correct `nextCursor`), server-side limit clamping.
- `ChainVerificationIntegrationTest`: intact chain and empty chain verify; and each of
  modified field, modified payload, broken previous hash, missing sequence, malformed stored
  hash, inconsistent chain head, and genesis-link violation is detected at the correct record.

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.
