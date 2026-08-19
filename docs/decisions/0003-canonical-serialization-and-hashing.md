# ADR 0003 — Canonical Serialization & Content Hashing

- **Status:** Accepted (pending engineer sign-off)
- **Date:** 2026-08-18
- **Context:** The tamper-evidence guarantee requires that logically-identical events always
  produce the same hash, and that any change to a protected field changes the hash. This ADR
  fixes the exact **protected hash projection**, the **canonicalization rules**, and the
  **hash formula**. Pure library code only — no persistence, API, security, or chaining is
  implemented here.

## Protected hash projection (what the hash covers)

The content hash commits to exactly these fields, in this fixed order
(`ProtectedEventProjection`):

```
1.  schemaVersion    (int,  > 0)          8.  outcome
2.  sequenceNumber   (long, > 0)          9.  businessReason   (nullable)
3.  eventId          (uuid string)       10.  eventTimestamp   (UTC µs-truncated, nullable)
4.  actorId                              11.  recordedAt       (UTC µs-truncated, nullable)
5.  actorType                            12.  payload          (canonicalized JSON)
6.  action                               13.  previousHash     (byte[32] -> 64-hex, null for genesis)
7.  resourceType, resourceId
```

**Explicitly EXCLUDED** (documented boundary): the internal surrogate `id` (storage-only),
and any future mutable lifecycle state (redaction/archival) — lifecycle changes are recorded
as separate hash-chained amendments in later steps, never by mutating this projection.

## Canonicalization rules

1. **Fixed top-level field order** — emitted in the projection's declared order above (NOT
   alphabetical). The order is hard-coded in the serializer, so it never depends on map or
   reflection iteration.
2. **Object keys sorted** — within the JSON `payload`, every object's keys are sorted by Java
   `String.compareTo` (UTF-16 code-unit order), applied recursively. **Array element order is
   preserved** (arrays are ordered by definition).
3. **UTF-8** — the canonical form is a Java `String`; the hash is over its UTF-8 bytes.
   Non-ASCII characters are emitted literally (valid JSON) and become UTF-8 bytes at hash time.
4. **Explicit nulls** — a null protected field is emitted as the JSON `null` token, never
   omitted. `null` is therefore distinct from the empty string `""`.
5. **Timestamp normalization (PostgreSQL-safe, microsecond precision).** `OffsetDateTime`
   values are (a) converted to UTC, (b) **truncated to microseconds**, then (c) formatted with
   the fixed pattern `uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'` (exactly **6** fractional digits).
   PostgreSQL `TIMESTAMPTZ` stores microseconds, not nanoseconds, so any sub-microsecond
   component is dropped *before* hashing — the canonical form is therefore identical before
   persistence and after a reread. **The append service MUST persist the same
   microsecond-truncated `Instant`/`OffsetDateTime` it hashed.** Equal instants in different
   offsets canonicalize identically.
6. **`previousHash` encoding.** The preceding record's 32-byte content hash is rendered as
   **exactly 64 lowercase hexadecimal characters** (one deterministic representation). The
   genesis record (sequence 1) has no predecessor and is emitted as the JSON `null` token.
   The projection carries `previousHash` as `byte[]` (32 bytes, validated) so the hex
   encoding is owned solely by the serializer, not by callers. The projection **defensively
   copies** the array on construction and returns a copy from its accessor, so neither the
   caller's original array nor a value obtained from the accessor can mutate the projection's
   integrity-relevant state.
7. **No insignificant whitespace** — no spaces/newlines outside string values.
8. **Numbers** — payload numbers are emitted via `BigDecimal.stripTrailingZeros().toPlainString()`
   for a stable numeric text.

## Hash formula

```
canonical      = CanonicalJsonSerializer.canonicalize(projection)   // a String
content_hash   = SHA-256( UTF-8-bytes( canonical ) )                // exactly 32 bytes
```

The 32-byte result matches the `BYTEA` 32-byte CHECK from V1 (ADR 0002).

## Genesis convention (NO genesis hash)

There is deliberately **no** genesis-hash sentinel. Matching the already-migrated V1 schema
(ADR 0002):
- empty chain head: `current_sequence = 0`, `current_hash = null`;
- first event: `sequence_number = 1`, `previous_hash = null`; its canonical projection
  contains `"previousHash":null`;
- later events (`sequence_number > 1`) carry the previous event's 32-byte `content_hash`
  (rendered as 64-char lowercase hex in the canonical form).

`ProtectedEventProjection` enforces this at construction: seq 1 ⇒ null previousHash; seq > 1 ⇒
non-null 32-byte previousHash. (An earlier draft proposed a
`SHA-256("AUDIT_LOG_GENESIS_V1")` sentinel — that has been removed as it contradicted the
migrated schema.)

## Why not rely on Jackson's default serialization

Jackson is used only to **parse** the payload into a tree; the deterministic re-emission
(sorted keys, explicit nulls, fixed number/whitespace rules) is done by our own writer.
Default ObjectMapper output is not guaranteed stable across versions/configuration, and the
tamper guarantee must not depend on library defaults. (Note: Spring Boot 4.1 ships **Jackson
3.x**, whose base package is `tools.jackson.*`, not `com.fasterxml.jackson.*`.)

## Trade-offs / limitations

- **UTF-16 code-unit key ordering** is deterministic and simple but not identical to Unicode
  code-point ordering for characters outside the BMP. It is fully stable and documented; if a
  future requirement needs code-point ordering, it becomes a new `schemaVersion`.
- The canonical form is bespoke (not JCS/RFC 8785). This is intentional for control and
  reviewability; `schemaVersion` lets the scheme evolve without ambiguity.

## Validation

`CanonicalHashTest` (21 pure unit tests): determinism, fixed non-alphabetical top-level order,
payload key-order independence (incl. nested) with array order preserved, UTF-8 stability and
distinctness, null-vs-empty distinction and explicit null emission, timestamp UTC
normalization with **microsecond** precision (equal instants equal; sub-microsecond
differences collapse to the same hash; a 1-microsecond difference changes the hash; a
persist/reread round-trip does not change the canonical form; `Z` rendering with 6 digits),
`previousHash` rendered as 64 lowercase hex chars (null for genesis), and that changing **any**
protected field changes the hash.

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.
