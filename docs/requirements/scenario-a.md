# Scenario A — Greenfield: Core Audit Log Service

> **Status: requirement analysis only.** Nothing described here is implemented yet.
> This document normalizes the assignment text into an engineering problem and records
> where we made assumptions versus where the assignment is explicit.

## A.1 Assignment requirements (as given)

These are taken directly from the assignment and are **not** our invention:

- **Write API** accepting an event record with at minimum:
  - `eventType` — what happened (e.g. `USER_LOGIN`, `RECORD_UPDATED`, `PERMISSION_GRANTED`)
  - `actorId` — who or what caused the event
  - `resourceType` — the type of resource affected
  - `resourceId` — the specific resource affected
  - `payload` — a structured object with event-specific detail
  - `timestamp` — when the event occurred (caller-supplied or server-assigned; choice must be documented)
- Records are **append-only**: the API must **not** expose update or delete.
- **Query API** retrieving events, filterable by any combination of:
  - `actorId`
  - `resourceType` and `resourceId`
  - `eventType`
  - time range (`from` / `to`)
  - with **pagination** for large result sets.
- **Tamper evidence — hash chain.** Each stored record must include:
  - a hash of its own content, and
  - a hash of the immediately preceding record (or a defined genesis value for the first record),
  - together forming a chain where any modification to a past record invalidates its own hash and every subsequent hash.
- **Chain verification endpoint** `GET /audit/verify` that walks the full chain and reports:
  - whether the chain is intact, and
  - if broken, which record is the first inconsistency and what type of violation was detected.
- Validation is performed **through the APIs**: write events, query, verify, then modify a record directly in the data store and verify again to confirm detection. No external consumer required.

## A.2 Our normalization & assumptions

These are engineering decisions **we** made to resolve ambiguity in the assignment. They
are assumptions, not assignment mandates, and are open to change.

| # | Decision | Rationale | Assumption or mandated? |
|---|---|---|---|
| A-1 | **Timestamp:** caller supplies `eventTimestamp` (business time); server always assigns `recordedAt` (ingestion time). Both are stored and both are covered by the content hash. | The assignment allows either and asks us to document the choice. Separating business time from ingestion time prevents a caller from controlling ordering/ingestion time while still honoring when the event "occurred." | Assumption (assignment leaves the choice to us) |
| A-2 | **Hash algorithm:** SHA-256 over a **canonical** serialization (fixed field order, sorted JSON keys, UTF-8, ISO-8601 UTC timestamps, explicit nulls). | Deterministic and standard; avoids logically-identical JSON hashing differently. Canonicalization is done by a dedicated serializer, not framework defaults. | Assumption (algorithm not mandated) |
| A-3 | **Genesis value:** `previousHash` of the first record = `SHA-256("AUDIT_LOG_GENESIS_V1")`. | The assignment requires "a defined genesis value"; we define it explicitly and version it. | Assumption (specific value is ours) |
| A-4 | **Ordering & concurrency:** a single linear chain enforced by locking a singleton chain-head row (`SELECT ... FOR UPDATE`) per append. | Guarantees a deterministic single chain under concurrent writes. Throughput-limited by design, which is acceptable and honest for an audit log. | Assumption (mechanism not specified) |
| A-5 | **Pagination:** cursor-based on a monotonic sequence number, not offset. | Stable under concurrent inserts (offset pagination shifts as rows are added). | Assumption (style not specified) |
| A-6 | **Verification output:** on break, report the first inconsistent sequence number, its event id, and a typed violation (e.g. content-hash mismatch, previous-hash mismatch, sequence gap). | The assignment asks for "which record" and "what type of violation"; we enumerate explicit violation types. | Assumption (violation taxonomy is ours) |
| A-7 | **Payload** is stored as structured JSON (JSONB in PostgreSQL). | Matches "a structured object"; enables querying and canonical hashing. | Assumption (storage type is ours) |

## A.3 Questions we would ask stakeholders

If a product owner were available, we would ask (and, absent answers, proceed on the
assumptions above):

1. Should `eventTimestamp` be rejected if it is in the future or far in the past, or accepted as-is and merely recorded?
2. Are there maximum sizes / allowed schemas for `payload`, or is it free-form?
3. Is a single global chain acceptable, or is per-tenant / per-resource chaining required (which changes ordering and verification)?
4. What are expected write throughput and query volumes? (Drives whether the single-lock chain is acceptable.)
5. Must verification be constant-time / streaming for very large chains, or is a full walk acceptable for the prototype?
6. Are duplicate events (same fields) legitimate, or should they be de-duplicated?

## A.4 Prototype scope for Scenario A

**In scope (planned):** write API, query API with the required filters + cursor
pagination, SHA-256 hash chain with documented genesis, `GET /audit/verify` with typed
violations, and validation via direct data-store tampering.

**Out of scope / deferred:** authentication is introduced later (Scenario C / hardening);
horizontal scaling and sharded chains are documented as future work, not built;
streaming/constant-memory verification for very large chains is not implemented in the
prototype.

> None of the above is implemented in this commit. This document defines *what* Scenario
> A will do, not a claim that it already does it.
