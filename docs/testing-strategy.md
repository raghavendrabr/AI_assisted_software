# Testing Strategy, Coverage & Limitations

## Approach

Two layers, both run by `./mvnw test`:

- **Unit tests** (fast, no Spring/DB) — the pure hashing/crypto and validation logic:
  canonical serialization + SHA-256 determinism, redaction commitment (salt length, domain
  separation, no-plaintext-leak), manifest hashing (length-prefixed unambiguity), API-key config
  validation (fail-fast), the Ed25519 signer's fail-closed key policy, and the exception→status
  mapping.
- **Integration tests** (Testcontainers, **real PostgreSQL 16**) — everything that depends on the
  database and its concurrency/locking semantics: schema constraints, transactional append with
  `SELECT ... FOR UPDATE`, query/pagination, full chain verification incl. all tamper cases,
  redaction, archival, and the signed-export round-trip with the standalone verifier.

Integration tests use real PostgreSQL (not H2) so `SELECT ... FOR UPDATE`, JSONB, and CHECK
constraints behave exactly as in production. **This requires Docker running.**

## What is covered (135 tests)

- **Hashing (28):** determinism; field-order and payload-key-order independence; UTF-8; explicit
  null handling; microsecond timestamp normalization + persist/reread stability; 64-hex previous
  hash; defensive-copy immutability; per-field sensitivity; redaction commitment binding & salt
  length; manifest-hash unambiguity.
- **Schema (11):** Flyway V1 applies; both tables + seed row; valid genesis/later events; rejection
  of invalid sequence, hash length, previous-hash rule, duplicate id, duplicate sequence.
- **Append (12):** genesis + linkage; microsecond-timestamp persistence; validation → 400;
  duplicate id → 409 (pre-check and DB-constraint paths, never 500); 25-way concurrent append →
  gap-free linked chain; no update/delete endpoint.
- **Query/verify (18):** filter + AND-combination; stable cursor pagination (limit+1, exact-limit
  final page, extra row); `limit<=0` and inverted range → 400; intact/empty chain; detection of
  modified field, modified payload, broken previous hash, missing sequence, malformed stored hash,
  chain-head mismatch, genesis-link violation; verification consistent under concurrent appends.
- **Redaction (19):** envelope stored; authorized redaction keeps `content_hash` and both chains
  intact; unbacked null → `REDACTION_UNBACKED`; tampered value → `COMMITMENT_MISMATCH`; tampered
  amendment → `AMENDMENT_CHAIN_BROKEN`; unknown/non-redactable/already-redacted → error;
  concurrent same-field redaction → exactly one succeeds; failed redaction rolls back; no plaintext
  in amendment.
- **Retention (19):** oldest-contiguous-prefix archival + chain intact; nothing-eligible → error;
  modified/deleted archived record, duplicated sequence, and tampered manifest detected; redaction
  on archived events; concurrent archive moves each record once; full rollback leaves everything
  unchanged; search/cursor across the archive boundary; compliance includes an archived access once.
- **Export (16):** signed bundle verifies offline (incl. archived + redacted); modified/reordered/
  removed event and amendment, redacted-without-amendment, non-matching injected event, duplicate
  event, tampered manifest, and wrong public key rejected; signer fail-closed policy; exactly-one-
  filter enforcement.
- **Security (19):** 401/403/2xx per role across endpoints; unlisted endpoint denied (fail-closed);
  duplicate/multi-role key config fails fast without leaking the key; redaction/archival ADMIN-only.
- **Compliance (5):** success + denied client-account access; filters; non-client-account excluded;
  content-hash tie-back; inverted range → 400.

## What is NOT covered (and why)

- **Load/performance testing** — out of scope for a prototype; the single-chain lock's throughput
  ceiling is a documented design property, not something the test suite measures.
- **Multi-instance / HA behavior** — single-instance prototype.
- **Real KMS / OAuth2 flows** — prototype uses static API keys and a file/ephemeral signing key;
  production integrations are design-only.
- **Global export completeness** — deliberately not provable offline (documented limitation).
- **Fuzz/property-based testing** of the canonical serializer — the determinism properties are
  covered by targeted cases rather than generative fuzzing.

## Running

```
docker compose up -d        # PostgreSQL (Docker required for integration tests)
./mvnw test                 # all 135 tests
./mvnw test -Dtest=ChainVerificationIntegrationTest   # a single class
```
