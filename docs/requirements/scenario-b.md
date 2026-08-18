# Scenario B — Extend Your Own System: Retention & Redaction

> **Status: requirement analysis only.** Nothing described here is implemented yet.
> Extends Scenario A. Records where the assignment is explicit versus where we made
> engineering decisions.

## B.1 Assignment requirements (as given)

- **Retention policy.** Records older than a configurable window should be
  **archivable or soft-deletable**. The chain verification endpoint must handle archived
  records correctly and **not report a false-positive break** for records legitimately
  archived per policy.
- **Structured redaction.** Certain fields within a record's `payload` may contain
  sensitive data (e.g. account numbers, personal identifiers) that must be
  **redactable** to satisfy privacy requirements — **without breaking the hash chain**.
  The assignment explicitly notes this is a genuine engineering problem: the original
  hash covers the original value, so naive removal invalidates the hash. We must design
  a redaction scheme that satisfies **both** tamper-evidence and privacy, and document
  the approach, trade-offs, and limitations.
- **Bulk export.** An endpoint to export all records for a given `resourceId` or
  `actorId` as a **self-contained, verifiable bundle**. The bundle must include enough
  chain metadata for a recipient to **independently verify** the records have not been
  altered since export.

## B.2 Our design decisions & assumptions

These resolve *how* we will meet B's requirements. They are our decisions, refined
through human design review (see `docs/ai-usage-log.md`), not assignment mandates.

| # | Decision | Rationale | Assumption or mandated? |
|---|---|---|---|
| B-1 | **Immutable base events + separate amendment chain.** Lifecycle changes (redaction, archival) are recorded as new, independently hash-chained `AuditAmendment` records rather than mutations of the original row. | Lets us distinguish an *authorized* redaction from *tampering*, and keeps lifecycle state inside integrity protection. | Assumption (mechanism is ours) |
| B-2 | **Redaction via salted commitment.** Each declared-redactable field stores `{salt, commitment=SHA-256(salt‖value), value}`. The content hash commits to `{salt, commitment}` and **excludes only** the mutable plaintext `value`. Redaction nulls `value` (which the hash never covered) and is backed by a `REDACTION` amendment. | Redaction never touches hashed content, so the chain stays intact; and a null value is only valid if a matching amendment exists — silent nulling is detectable. | Assumption (scheme is ours) |
| B-3 | **Honest redaction limitation.** Because both `salt` and `commitment` are retained, a **low-entropy** redacted value can be brute-forced offline. The commitment provides *tamper-evidence*, **not confidentiality-at-rest**. Production would layer crypto-erasure (encrypt value, hash ciphertext, destroy key). | We will not overstate the privacy guarantee; the trade-off is documented explicitly. | Assumption + explicit limitation |
| B-4 | **Retention by archival, not deletion.** Old records move from the active table into an archive table (sequence numbers preserved), recorded by an `ARCHIVE` amendment + an `archive_manifest`. Verification loads active ∪ archived in one ordered stream, so archival is not a false break. | Meets "archivable/soft-deletable" while keeping verification evidence intact. | Assumption (mechanism is ours) |
| B-5 | **Archive binding.** The `ARCHIVE` amendment's hashed detail embeds `{manifestId, manifestHash, fromSequence, toSequence, recordCount}`, cryptographically binding exactly which range was archived. | Prevents swapping/altering a manifest without breaking the amendment chain. | Assumption (mechanism is ours) |
| B-6 | **Export proof via Ed25519 signature.** The bundle carries a canonical manifest (export id, timestamp, filters, count, ordered event hashes, relevant amendment hashes, chain-head snapshot, signing-key id) signed with a **dedicated Ed25519 export-signing key** — never the API auth key. A standalone verifier + published public key ship with the repo. | A predecessor hash alone cannot authenticate a filtered subset, and a plain bundle hash is recomputable by an attacker. A signature the attacker cannot forge is required. | Assumption (mechanism is ours) |
| B-7 | **Export completeness is explicitly out of scope.** The signed bundle proves the exported records have not changed since export; it does **not** prove global query completeness (that no other matching records exist) without exporting the full chain or a Merkle accumulator. | Honest boundary; documented, not silently omitted. | Assumption + explicit limitation |

## B.3 Questions we would ask stakeholders

1. What is the retention window, and is it fixed policy or per-resource/per-tenant configurable?
2. After archival, must archived records still be queryable through the normal query API, or only through verification/export?
3. Which payload fields are considered sensitive/redactable — is this a fixed schema or declared per-write? (Our current design: declared per-write via `redactableFields`.)
4. Does redaction need to be *irreversible confidentiality* (true erasure) or *tamper-evident privacy* (value hidden, integrity provable)? This determines whether crypto-erasure is required now vs. deferred.
5. Who is authorized to redact and to archive? (Our current design: ADMIN role.)
6. What format must the export bundle be (JSON assumed), and who are the recipients / what tooling will they use to verify?

## B.4 Prototype scope for Scenario B

**In scope (planned):** amendment chain; salted-commitment redaction endpoint;
archival with manifest + merged-stream verification; Ed25519-signed export bundle +
standalone verifier; adversarial tests for each.

**Out of scope / deferred (documented boundaries):** crypto-erasure / KMS integration
(design-only ADR); Merkle-tree completeness proofs; automatic time-triggered retention
jobs (archival will be triggered explicitly via endpoint in the prototype); external
delivery of export bundles.

> None of the above is implemented in this commit.
