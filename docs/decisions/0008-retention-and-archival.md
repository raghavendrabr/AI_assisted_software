# ADR 0008 — Retention & Archival

- **Status:** Accepted (pending engineer sign-off)
- **Date:** 2026-08-18
- **Context:** Scenario B retention: old records must be archivable/soft-deletable without the
  chain verifier reporting a false break. Signed export is **not** part of this commit.

## Migration (V3)

- `audit_event_archive` — mirrors `audit_event`'s integrity columns EXACTLY (sequence, hashes,
  payload, original `event_timestamp`/`recorded_at`) plus `archived_at`. Same CHECK constraints
  (32-byte hashes, genesis rule, positive sequence). Sequence numbers are preserved; a sequence
  is **moved**, never duplicated, so it stays unique across active ∪ archive.
- `archive_manifest` — one row per archival operation: `manifestId, fromSequence, toSequence,
  recordCount, firstHash, lastHash, archivedAt, authorizedBy, manifestHash`, with range/count/
  hash-length CHECKs.

## Archival transaction (atomic, head-locked)

`POST /api/v1/audit/retention/archive` (ADMIN), one transaction:
1. lock the chain head `FOR UPDATE`;
2. select the **oldest CONTIGUOUS prefix** of active events with `event_timestamp < cutoff`
   (stop at the first non-eligible event — we never leave a hole in the active range);
3. **COPY** those rows into `audit_event_archive` (all integrity fields preserved) — copy BEFORE
   any delete;
4. create the `archive_manifest`;
5. append an `ARCHIVE` amendment whose canonical detail embeds
   `{manifestId, manifestHash, fromSequence, toSequence, recordCount}`, and advance the amendment
   head;
6. **DELETE** the copied rows from `audit_event`.
Any failure rolls the whole thing back (no partial move, no orphan manifest/amendment) —
verified by test.

## Manifest hash formula (length-prefixed, unambiguous)

```
manifest_hash = SHA-256(
    lp("AUDIT_ARCHIVE_MANIFEST_v1") | lp(manifestId) | lp(fromSequence) | lp(toSequence) |
    lp(recordCount) | lp(hex(firstHash)) | lp(hex(lastHash)) | lp(archivedAt UTC µs) |
    lp(authorizedBy) )
where  lp(x) = int64_be(len(utf8(x))) || utf8(x)
```
Each component is **length-prefixed** (8-byte big-endian UTF-8 length before its bytes), so the
encoding is unambiguous regardless of field content — no delimiter is used, and no value
(including `authorizedBy`, the only free-text field) can be crafted to forge a different field
layout. `firstHash`/`lastHash` are the content hashes of the first/last archived record. The
ARCHIVE amendment binds `manifestHash` into the amendment chain, so the archived range cannot be
altered without breaking that chain.

(An earlier draft used `0x1F` delimiters, which would only be unambiguous if `authorizedBy` could
never contain `0x1F`; length-prefixing removes that assumption entirely.)

## Verification behavior (active + archive as one chain)

`verify()` merges active and archived events into one `sequenceNumber`-ordered stream and walks
it as a single chain (no physical FK ties an amendment to the active table only). Archival
therefore never causes a false break. It additionally checks each manifest:
- the `manifest_hash` recomputes from the manifest fields;
- an intact `ARCHIVE` amendment binds the manifest (id + hash);
- the actual archived records for the range match `recordCount` and the `first/last` hashes.
New violation type `ARCHIVE_PROOF_MISMATCH` covers manifest count/range/hash mismatches.
Detected: a **missing** archived record (`SEQUENCE_GAP` in the merged stream and/or
`ARCHIVE_PROOF_MISMATCH` on count), a **modified** archived record (`CONTENT_HASH_MISMATCH`), and
manifest tampering (`ARCHIVE_PROOF_MISMATCH`).

## Read paths & redaction

- **Search** (`GET /audit/events`) defaults to active-only; `includeArchived=true` merges
  archived events, ordered together by sequence. Documented, explicit (not silent omission).
- **Compliance report** defaults `includeArchived=true` (regulators need the full history).
- **Redaction** works for archived events: the redaction service locates the event in active OR
  archive and nulls the plaintext in the correct table; the chain stays intact.

## Retention policy assumptions & production limitations (documented)

- **Policy:** archival is **manually triggered** via the endpoint with an explicit `olderThan`
  cutoff; there is no scheduled/automatic retention job in the prototype (a scheduler would call
  the same service in production).
- **Contiguous-prefix only:** we archive only the oldest contiguous run older than the cutoff, so
  the active range never develops holes; a non-eligible event blocks archival of older-by-time
  events that sit behind it in sequence. This keeps verification simple and is a deliberate,
  documented constraint.
- **Storage:** archive is another table in the same PostgreSQL for the prototype; production would
  use cheaper/cold storage (object store, separate DB) with the same manifest binding.
- **Deletion:** records are moved, never destroyed. True hard-deletion for legal erasure is out of
  scope; it would interact with the hash chain and is future work (cf. redaction's crypto-erasure).

## Validation

`ArchiveIntegrationTest` (8): archives the oldest contiguous prefix and moves records with the
chain still intact; archives only the contiguous oldest prefix; nothing-eligible → error;
modified / deleted archived record and tampered manifest are detected; redaction works on an
archived event with the chain intact; concurrent archive attempts move each record exactly once
with the chain intact.

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.
