# ADR 0007 — Amendment Chain & Structured Redaction

- **Status:** Accepted (pending engineer sign-off)
- **Date:** 2026-08-18
- **Context:** Scenario B's hardest problem: make a payload field redactable to satisfy privacy,
  **without breaking the hash chain** and while keeping the redaction provable (not
  indistinguishable from tampering). This introduces the second (amendment) chain foreseen in
  the plan and the salted-commitment redaction scheme.

## Two chains, immutable base events

- **Base events stay immutable** except that a declared-redactable field's plaintext `value`
  may go present → null. That `value` is **excluded from `content_hash`** by construction, so
  nulling it leaves the event chain byte-identical.
- **Lifecycle changes are separate, independently hash-chained `audit_amendment` records** (V2),
  not mutations of the base row. A `REDACTION` amendment records who / when / which field.
  Amendment genesis mirrors the event chain: `amendment_seq 1` has null
  `previous_amendment_hash`; later amendments carry the prior amendment's 32-byte hash. The
  singleton chain head tracks both tips; amendment appends lock it `FOR UPDATE`.

## Salted-commitment redaction scheme

At write time, for each field named in the request's `redactableFields`:
- generate a fresh **`SecureRandom`** `salt` of **32 bytes** (>= 16-byte minimum enforced);
- compute a **domain-separated commitment bound to the event id and field path**:
  `commitment = SHA-256( "AUDIT_REDACT_v1" | eventId | fieldPath | salt | canonical(value) )`
  with `0x1F` (unit separator) delimiters — so a commitment can never be replayed for a
  different event or field;
- **store** `{ "salt": <hex>, "commitment": <hex>, "value": <plaintext> }`;
- the **hash payload** (what `content_hash` commits to) contains `{ salt, commitment }` for that
  field — **never the plaintext value**.

Redaction (`POST /api/v1/audit/events/{seq}/redact`, ADMIN, single transaction):
1. validate the target event exists and the field is a redactable envelope with a non-null value
   (re-redaction rejected);
2. append a `REDACTION` amendment (locking the head) and advance the amendment tip;
3. null the field's `value` in the stored payload (the only permitted base mutation).

Because the hash never covered `value`, `content_hash` is unchanged and the event chain stays
intact. A null value is legitimate **only** when a matching `REDACTION` amendment exists.

## Verification additions

The verifier now walks BOTH chains and recomputes base content hashes over the **hash payload**
(redactable envelopes contribute `{salt, commitment}`), so redacted events still verify. New
violation types:
- `AMENDMENT_CHAIN_BROKEN` — amendment sequence/linkage/hash invalid, or an amendment modified;
- `REDACTION_UNBACKED` — a redactable field's value is null with no authorized `REDACTION`
  amendment (an attacker's silent null);
- `COMMITMENT_MISMATCH` — a present value doesn't match its commitment (value/salt tampered).
The chain-head check now also verifies the amendment tip (sequence + hash).

## Honest limitation (privacy)

Because both `salt` and `commitment` are retained, a redacted **low-entropy** value (e.g. a
short account number) is vulnerable to offline brute-force / dictionary guessing. **This scheme
provides tamper-evidence, not confidentiality-at-rest.** For true confidentiality, production
would combine it with crypto-erasure (encrypt the value, cover the ciphertext in the hash,
destroy the key on redaction) — documented as the alternative, not implemented here. We do not
claim the redacted plaintext is unrecoverable.

## Trade-offs / notes

- The stored payload and the hash payload are two representations of the same fields; the
  verifier always derives the hash payload from what is stored, so it is consistent before and
  after redaction.
- `commitment` uses `SHA-256(salt ‖ value.toString())`; the value's compact JSON text is the
  committed form. `schema_version` gates future changes to this rule.
- Redaction is ADMIN-only; the base event's `content_hash` and all non-redacted fields remain
  immutable.

## Security properties (confirmed by test)

- **SecureRandom salt, ≥ 16 bytes:** salts are 32 bytes from `SecureRandom`; `commitment(...)`
  rejects a salt shorter than 16 bytes.
- **Domain-separated commitment bound to eventId + field path:** changing the eventId or the
  field name changes the commitment even with identical salt+value (no cross-event/field replay).
- **No plaintext in amendment records or logs:** the amendment `detail` is `{field}` (+ actor);
  the redacted plaintext never appears in the amendment, and the hash payload / commitment
  contain no plaintext. No component logs the value.
- **Concurrent same-field redaction — exactly one succeeds:** the head lock is acquired BEFORE
  re-reading the field state (and the persistence context is cleared post-lock), so the
  check-then-redact is atomic; of N concurrent attempts exactly one commits, the rest are
  rejected, one amendment is written, and the chain verifies.
- **Atomic rollback:** a failing redaction (e.g. non-redactable field) writes nothing — the base
  event `content_hash`, the amendment table, and the amendment head are all unchanged, and both
  chains still verify.

## Validation

`RedactionIntegrationTest` (11) + `RedactablePayloadProcessorTest` (6): write stores the
envelope and verifies; authorized redaction nulls the plaintext, is amendment-backed, leaves
`content_hash` unchanged, and both chains verify; unbacked null → `REDACTION_UNBACKED`; tampered
value → `COMMITMENT_MISMATCH`; tampered amendment → `AMENDMENT_CHAIN_BROKEN`; unknown target →
404; non-redactable / already-redacted → error; salt ≥ 16 bytes; commitment bound to
eventId/field; no plaintext in hash payload/commitment/amendment; concurrent same-field redaction
→ exactly one succeeds; failed redaction rolls back leaving both chains unchanged. Plus
`ApiKeySecurityIntegrationTest` confirms redaction is ADMIN-only (WRITER/COMPLIANCE → 403, no
key → 401).

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-18.
