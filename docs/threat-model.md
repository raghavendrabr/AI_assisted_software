# Threat Model

Scope: the tamper-evidence and access-control guarantees of the audit log service. The central
adversary is someone with **direct data-store access** (the assignment's core validation) plus
API-level attackers.

## Assets

- The integrity of the append-only event history (no undetectable modification/deletion).
- The provability of authorized lifecycle changes (redaction, archival).
- The confidentiality of the export-signing private key and the API keys.

## Adversaries & mitigations

| Adversary / attack | Mitigation | Detection |
|---|---|---|
| **Direct DB tamper** — modify a stored event field or payload | `content_hash` covers all integrity fields; verifier recomputes it | `CONTENT_HASH_MISMATCH` |
| **Direct DB tamper** — change a record's `previous_hash` / reorder | chain linkage checked in walk order | `PREVIOUS_HASH_MISMATCH` |
| **Direct DB tamper** — delete a record | strict sequence walk (active∪archive) | `SEQUENCE_GAP` |
| **Direct DB tamper** — corrupt a stored hash length | DB CHECK + verifier length check | `MALFORMED_STORED_HASH` |
| **Direct DB tamper** — desync the chain-head row | head compared to recomputed tip | `CHAIN_HEAD_MISMATCH` |
| **Silent redaction** — null a redactable value without authorization | null value requires a backing REDACTION amendment | `REDACTION_UNBACKED` |
| **Value/salt tamper** on a redactable field | value re-checked against its commitment | `COMMITMENT_MISMATCH` |
| **Amendment tamper/reorder/delete** | amendment chain recomputed + linked | `AMENDMENT_CHAIN_BROKEN` |
| **Archive tamper** — modify/delete/duplicate archived record or swap manifest | merged-stream walk + manifest binding | `ARCHIVE_PROOF_MISMATCH` / `SEQUENCE_GAP` |
| **Forged commitment replay** across event/field | commitment domain-separated + bound to eventId+field | recompute fails |
| **Export tamper** — modify/reorder/remove/insert records or amendments | Ed25519 signature over a canonical manifest; standalone recompute | signature/hardcheck fail |
| **Export forgery** — fabricate a bundle | requires the private signing key (never the API key; never committed) | signature fails |
| **Unauthorized API access** | `X-API-Key` → server-side role; fail-closed `denyAll()` | 401 / 403 |
| **Client-supplied role escalation** | role never accepted from the client; resolved server-side | — |
| **Weak/duplicate key config** | fail-fast on duplicate/multi-role keys; whitespace treated as unset | startup abort |
| **Deployed with no signing key** | ephemeral key only under local/test; else fail closed | startup abort |

## Residual risks / assumptions

- **Attacker who can rewrite the ENTIRE chain consistently** (recompute every hash + head) inside
  the DB is not detectable by the verifier alone — this is inherent to a self-contained hash chain.
  Mitigation in production: periodically **publish the chain-head hash** to an external, tamper-
  resistant location (notary/transparency log) so a wholesale rewrite is detectable. Out of scope
  for the prototype; noted as future work.
- **Redaction confidentiality:** salt + commitment allow offline brute-force of low-entropy values.
  Tamper-evidence, not confidentiality-at-rest (ADR 0007).
- **Export completeness:** a signed bundle is not proof that no other matching records exist.
- **Key management:** file/ephemeral keys are prototype-grade; production needs a KMS/secret manager,
  key rotation, and trusted public-key distribution (a `signingKeyId` is a hint, not trust — ADR 0009).
- **Transport security:** TLS/mTLS is assumed to be terminated by the deployment environment; not
  configured in the prototype.
