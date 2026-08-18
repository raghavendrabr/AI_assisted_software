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

## How to read this log going forward

Each future task (implementation, tests, refactors) will get its own `AI-0xx` entry
recording intent, what the AI produced, what was accepted/modified/rejected, engineer
validation performed, and a human sign-off. High-impact changes require an explicit
engineer sign-off before they are relied upon.
