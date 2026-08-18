# Cross-Cutting Assumptions & Open Questions

> **Status: requirement/design stage.** These are engineering assumptions we adopted to
> proceed in the absence of a live stakeholder. They are **ours**, not assignment
> mandates, and are revisable. Scenario-specific assumptions live in the per-scenario
> requirement docs; this file captures decisions that span the whole system.

## 1. Technology & versioning

| Assumption | Rationale | Verification status |
|---|---|---|
| **Java 21** as the runtime. | Current LTS; required baseline for the Spring Boot 4.x line. | To be pinned in `pom.xml`. |
| **Spring Boot 4.1.x** (current stable GA line). | Verified via endoflife.date that the 3.5 line reached open-source EOL on 2026-06-30 and that 4.1 is the current GA line with OSS support through 2027-07-31. Building on a supported line is defensible. | Verified against endoflife.date during planning; exact patch to be pinned at scaffold time and recorded in an ADR. |
| **springdoc-openapi 3.1.x**, **not** 2.8.x. | springdoc 2.8.x targets Spring Boot 3.x; the 3.x springdoc line (v3.1.0 parents on Boot 4.1.0) is the one compatible with Spring Boot 4.x. Mixing a Boot-3 springdoc with Boot 4 would be an incompatibility. | Verified against springdoc release notes during planning; to be confirmed again at scaffold time before writing `pom.xml`. |
| **PostgreSQL 16** as the datastore. | Real `SELECT ... FOR UPDATE` semantics and JSONB; matches an enterprise target. | To be configured via Docker Compose (not yet present). |
| **Testcontainers (real PostgreSQL)** for integration tests. | Highest fidelity for locking/concurrency behavior, which is central to chain correctness. Requires Docker to be running for the test suite. | To be added with the test code. |
| Flyway for schema migrations; versions governed by the Spring Boot BOM where possible. | Reduces version-drift risk; only springdoc is pinned outside the BOM. | To be pinned at scaffold time. |

> **Rule we are holding ourselves to:** framework/library compatibility will be
> re-checked against official documentation immediately before `pom.xml` is generated,
> and the verified versions recorded in an Architecture Decision Record. We do not pin
> versions from memory.

## 2. Data model & integrity

- **Two hash chains:** an immutable base-event chain and a separate amendment chain for
  lifecycle events (redaction, archival). The integrity-protected projection of every
  base event is immutable; only a declared redactable plaintext value (excluded from the
  base content hash) may transition present → null, and only via an amendment-backed,
  atomic operation.
- **Canonical serialization** (fixed field order, sorted keys, UTF-8, ISO-8601 UTC,
  explicit nulls) is done by a dedicated serializer, **not** framework JSON defaults, so
  logically-identical payloads hash identically.
- **SHA-256** for chaining; **Ed25519** for export signing (separate key from API auth).
- **Single global chain** ordered by a monotonic sequence, serialized by a locked
  singleton chain-head row. We assume a single chain is acceptable for the prototype;
  per-tenant/per-resource chaining is a possible future requirement (see open questions).

## 3. Time

- Callers may supply `eventTimestamp` (business time). The server always assigns
  `recordedAt` (ingestion time). Both are stored and hashed. We assume no strict
  validation of caller timestamps in the prototype beyond format (open question below).

## 4. Security (prototype posture)

- Authentication is via `X-API-Key` only; the key maps to a role **server-side**. The
  client never supplies its own role. Real keys and role mappings come from
  environment/local config that is git-ignored; committed config carries placeholders
  only.
- We assume API-key auth is an acceptable **prototype** stand-in; production would use
  OAuth2/OIDC + mTLS (documented as future work, not built).

## 5. Open questions we would raise with stakeholders

Consolidated from the scenario docs; unanswered items are proceeding on the assumptions above.

1. Is a single global chain acceptable, or is per-tenant/per-resource chaining required?
2. Expected write throughput and query volume (validates the single-lock design)?
3. Should caller-supplied timestamps be validated/bounded, or recorded as-is?
4. Is redaction required to provide true confidentiality (crypto-erasure) now, or is
   tamper-evident privacy sufficient for the prototype?
5. What is the retention window and is it globally fixed or configurable per scope?
6. Must archived records remain queryable via the normal query API, or only via
   verification/export?
7. Who are the export-bundle recipients and what verification tooling will they use?
8. For compliance reporting: does "access" include denied attempts and writes, and are
   regulators direct API consumers or served via internal compliance staff?

## 6. Explicitly deferred / out of scope (whole system)

- OAuth2/OIDC + mTLS authentication (design-only).
- KMS-backed crypto-erasure redaction (design-only ADR).
- Merkle-tree export completeness proofs.
- Time-triggered automatic retention jobs (archival triggered via endpoint in the prototype).
- Horizontal scaling / sharded chains.
- Regulator identity federation, scheduled/PDF reports, external delivery.

Each of these is a stated boundary, not a silent omission.
