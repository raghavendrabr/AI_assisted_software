# ADR 0009 — Ed25519-Signed Bulk Export & Standalone Verification

- **Status:** Accepted (pending engineer sign-off)
- **Date:** 2026-08-18
- **Context:** Scenario B bulk export: export all records for a `resourceId` or `actorId` as a
  self-contained bundle a recipient can **independently verify** has not been altered since export.
  Completes Scenario B.

## Why not a plain bundle hash

A filtered subset is not contiguous in the global chain, so `previous_hash` alone cannot
authenticate membership; and a plain `bundleHash` is trivially recomputable by an attacker who
edits the bundle. The bundle is therefore authenticated by a **detached Ed25519 signature over a
canonical manifest**, produced with a **dedicated export-signing key** that is never the API key.

## Signed manifest

```
manifest = { exportId, exportedAt, filterType, filterValue, recordCount,
             eventHashes[] (ordered content hashes), amendmentHashes[],
             chainHead{ lastEventSequence, eventHeadHash, lastAmendmentSeq, amendmentHeadHash },
             signingKeyId }
digest    = SHA-256( canonical(manifest) )        // length-prefixed encoding (unambiguous)
signature = Ed25519_sign(privateKey, digest)
```
The canonical encoding (`ExportManifestCanonicalizer`) is **length-prefixed** (8-byte big-endian
length before each component and each list element), so it is unambiguous regardless of content,
and identical on the server and the standalone verifier. `null` chain-head hashes use a distinct
sentinel so `null` ≠ `""`.

## Key handling

- The **Ed25519 private key** is loaded from `audit.export.private-key-path` (an environment /
  mounted-secret PEM); it is **never committed** (`.gitignore` blocks `*.pem` private keys).
- The **public key** (`audit.export.public-key-path`) may be committed (only `*_public.pem` is
  allowed through `.gitignore`).
- **Fail-closed dev fallback:** the EPHEMERAL non-production key is generated ONLY when an explicit
  `local` or `test` Spring profile is active. In any other (deployed/default) configuration, a
  missing `audit.export.private-key-path` is a **fatal startup error** — the service refuses to
  start rather than silently sign with a throwaway key. `scripts/generate-export-keypair.sh`
  generates a real local dev keypair (OpenSSL); production uses a managed KMS.
- The API authentication key is NEVER reused for signing.
- **Trust distribution:** the `signingKeyId` in the manifest is only a *hint* — it does NOT
  establish trust. A recipient must obtain the **public key through a trusted channel** (out of
  band, a PKI, or a known-good `*_public.pem`) and pass it explicitly to the verifier; verifying
  against the key embedded in the bundle only proves internal consistency, not authenticity. The
  standalone verifier supports a caller-supplied trusted public key for exactly this reason.

## Bundle & standalone verifier

The bundle carries the manifest, the exported `events[]` (full fields incl. redactable envelopes),
the relevant `amendments[]`, the `signature`, and the `publicKeyBase64`. `ExportBundleVerifier`
(and `ExportVerifyMain`, a runnable `java -cp app.jar ...ExportVerifyMain <bundle.json>
[trustedPublicKey.b64]`) depends only on the hashing library — no Spring, no DB — and checks:
1. the Ed25519 signature over the recomputed manifest digest (against the embedded key or a
   caller-supplied trusted key);
2. each event's recomputed `content_hash` (over the redaction-stable hash payload) equals its
   stated hash AND matches `manifest.eventHashes` in order → detects **modification** and
   **reordering**;
3. `recordCount` / hash-list lengths agree → detects **removal** and **insertion**.

## What the recipient CAN and CANNOT prove

- **CAN prove:** the exported records (these exact fields, this order, these redactions) have not
  changed since export, and the manifest was signed by the holder of the export private key.
- **CANNOT prove offline (documented limitation):** global query *completeness* — that no other
  matching records exist outside the bundle — without the full chain or a Merkle accumulator. The
  chain-head snapshot in the manifest lets a party who ALSO has the live service cross-check the
  tip, but a purely offline recipient cannot prove completeness. This is a stated boundary.

## Validation

`ExportIntegrationTest` (7): a signed bundle verifies offline (including archived + redacted
events); a modified event, reordered events, a removed event, a tampered manifest, and a wrong
public key are all rejected. `ApiKeySecurityIntegrationTest`: export is COMPLIANCE_READER/ADMIN
(WRITER → 403, no key → 401).

## Engineer sign-off
_<PENDING: Raghavendra to review/approve the signed-export design>_
