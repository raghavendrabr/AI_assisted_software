# Final Engineering Summary — OUTLINE (to be completed)

> **Status: outline only.** This document will be filled in as the system is built and
> validated. Sections below are placeholders describing what each will contain; they do
> **not** yet describe finished work, and no results are claimed here. Placeholders are
> marked `_<TBD>_`.

## 1. Plan & rationale
- _<TBD>_ Summary of the requirement interpretation and the chosen approach (tamper-evident
  append-only log via a SHA-256 hash chain; immutable base events + separate amendment
  chain for lifecycle events).
- _<TBD>_ Why a modular monolith on Java 21 / Spring Boot 4.1 / PostgreSQL rather than a
  distributed design.
- _<TBD>_ Link to the approved implementation plan and the per-scenario requirement docs.

## 2. Artifacts produced
- _<TBD>_ Enumerate delivered components (APIs, schema/migrations, canonical serializer +
  hasher, verification, redaction, retention/archive, export + standalone verifier,
  compliance report), each with its location. To be populated as code lands.

## 3. Architecture overview
- _<TBD>_ Components & responsibilities.
- _<TBD>_ Data model (base events, amendments, chain head, archive manifest) and the
  reasoning behind the two-chain design.
- _<TBD>_ API design and the authorization matrix.
- _<TBD>_ **Hash algorithm choice and chain design** (SHA-256, canonical serialization,
  genesis value) — required by the assignment; to be written up with the ADR.

## 4. Key decisions & trade-offs
- _<TBD>_ Concurrency via a locked chain-head row (correctness vs. throughput).
- _<TBD>_ Salted-commitment redaction (tamper-evidence vs. confidentiality; honest
  low-entropy limitation; crypto-erasure as the production alternative).
- _<TBD>_ Retention by archival with manifest binding (no false-positive breaks).
- _<TBD>_ Ed25519-signed export (why not a plain bundle hash or the API key).
- _<TBD>_ API-key auth for the prototype vs. OAuth2/OIDC + mTLS for production.
- _<TBD>_ Framework version selection (Spring Boot 4.1 / springdoc 3.1) and how it was verified.

## 5. Risks, failure scenarios & validation
- _<TBD>_ Threats considered (direct data-store tampering, unauthorized nulling,
  commitment/salt manipulation, amendment manipulation, archive removal/reordering,
  chain-head tampering, export tampering, unauthorized access).
- _<TBD>_ Validation strategy: unit tests (canonical serializer/hasher, Ed25519) and
  Testcontainers integration tests including the adversarial matrix. Results to be
  recorded here **after** the tests exist and run.

## 6. Assumptions & limitations
- _<TBD>_ Consolidated from `docs/assumptions.md` and the scenario docs.
- _<TBD>_ Explicit scope boundaries (crypto-erasure/KMS, Merkle completeness proofs,
  OAuth2/mTLS, scheduled/PDF reports, sharded chains) — stated, not hidden.

## 7. AI usage summary
- _<TBD>_ Condensed summary referencing `docs/ai-usage-log.md`: what AI accelerated, what
  the engineer corrected in review, and how ownership was retained.

## 8. How to run & verify (to be added with the code)
- _<TBD>_ Setup/run instructions and the end-to-end verification walkthrough. **Not
  written yet** — will be added only once the corresponding functionality exists.
