# ADR 0013 — Database Least-Privilege & DB-Level Immutability (Production Design, DESIGN-ONLY)

- **Status:** Proposed (design-only — **NOT implemented**)
- **Date:** 2026-08-19
- **Context:** The tamper-evidence guarantee currently rests on (a) the application exposing no
  update/delete endpoints and (b) the hash chain detecting any out-of-band mutation after the fact.
  At the **database privilege level** there is no defense-in-depth: the application connects as the
  **schema owner**, so a compromised app (or anyone with those credentials) could `UPDATE`/`DELETE`
  integrity columns directly, detectable only by later re-verification. This ADR designs a
  least-privilege + DB-level-immutability model and records **why it is deferred**.

> **This model is NOT implemented.** The prototype connects as the owning `audit` role. Nothing in
> this ADR is active in the current build.

## Current prototype (for contrast)
- `docker-compose.yml` creates a single role `audit` that owns the database and schema.
- `application.yml` connects the app as that same `audit` role.
- Flyway runs migrations as `audit`; the app reads/writes as `audit`.
- Integrity columns (`sequence_number`, `previous_hash`, `content_hash`, amendment hashes, manifest
  hashes) are protected only by shape `CHECK` constraints and by the app not exposing mutation
  endpoints — **not** by DB privileges or triggers.

## Why a naive REVOKE/GRANT breaks the app
The audit model is **not** purely append-only at the row level, so blanket `REVOKE UPDATE, DELETE`
would break legitimate flows:
- **Redaction** performs an `UPDATE` on the base/archive row to null the plaintext `value` inside the
  JSONB payload envelope (the hash is unaffected). A blanket `REVOKE UPDATE` would break redaction.
- **Archival** performs a `DELETE` on the active table (rows are *moved* to `audit_event_archive`
  after being copied) and `INSERT`s into the archive. A blanket `REVOKE DELETE` would break archival.
- **Chain head** advances via `UPDATE` on the singleton `audit_chain_head` row on every append.

So least-privilege here is **not** "no UPDATE/DELETE" — it is "UPDATE/DELETE only the specific
columns/rows these flows require, and never the integrity columns."

## Proposed roles
1. **`audit_owner`** (migration owner) — owns the schema; used **only** by Flyway to create/alter
   objects. Not used at runtime.
2. **`audit_app`** (runtime) — the role the application connects as. Granted the minimum needed:
   - `SELECT` on all audit tables;
   - `INSERT` on `audit_event`, `audit_amendment`, `audit_event_archive`, `archive_manifest`;
   - `UPDATE` on **`audit_chain_head`** (head advance) and on **only the redactable payload cell**
     of `audit_event`/`audit_event_archive` (see below);
   - `DELETE` on **`audit_event`** only (archival move) — never on `audit_amendment`,
     `archive_manifest`, or `audit_chain_head`;
   - `USAGE` on the sequence(s).
   The integrity columns must be unreachable by `UPDATE` from `audit_app`.

## Exact runtime operations that must remain possible
| Flow | Operation | Target |
|---|---|---|
| Append | INSERT | `audit_event`; UPDATE `audit_chain_head` (head advance) |
| Amend (redaction/archive) | INSERT | `audit_amendment`; UPDATE `audit_chain_head` |
| Redaction | UPDATE | `audit_event`/`audit_event_archive` — **payload value cell only**, never hashes/sequence |
| Archival | INSERT `audit_event_archive` + `archive_manifest`; DELETE `audit_event` |
| Verify / query / export | SELECT | all tables (read-only) |

## Protecting sequence / hash / integrity columns
PostgreSQL does not offer per-column `UPDATE` immutability via `GRANT` in a way that cleanly allows
"update this JSONB field but not these columns," so two complementary mechanisms are proposed:

1. **Column-scoped GRANTs where possible.** `GRANT UPDATE (payload) ON audit_event TO audit_app` —
   column-level UPDATE privilege limits `audit_app` to updating `payload` only; `sequence_number`,
   `previous_hash`, `content_hash`, `event_id`, timestamps are **not** grantable to it, so a direct
   `UPDATE ... SET content_hash = ...` is rejected by privilege. (Redaction only rewrites the JSONB
   `payload` cell, which is compatible with this.)
2. **`BEFORE UPDATE`/`BEFORE DELETE` triggers** as a backstop on `audit_event`/`audit_event_archive`
   /`audit_amendment`/`archive_manifest` that `RAISE EXCEPTION` when a protected column changes value
   (e.g. `OLD.content_hash IS DISTINCT FROM NEW.content_hash`, sequence changes, hash changes). The
   trigger permits the redaction payload-null transition and rejects everything else. This makes
   integrity-column immutability enforced **by the database**, independent of the app.

## Amendment / redaction / archival exceptions (must be allowed)
- Redaction's `payload` null transition — allowed by the payload-only trigger clause and the
  column-scoped `UPDATE (payload)` grant.
- Archival's `DELETE` on `audit_event` — allowed (rows are copied to the archive first; the archive
  copy is immutable). The `DELETE` is permitted on `audit_event` only.
- Chain-head `UPDATE` — allowed on `audit_chain_head` (not an integrity-protected historical row).

## SECURITY DEFINER alternative
Instead of granting `audit_app` direct DML, expose the mutating flows as **`SECURITY DEFINER`
stored procedures** owned by `audit_owner`: `append_event(...)`, `apply_redaction(...)`,
`archive_prefix(...)`. `audit_app` gets `EXECUTE` on these procedures and **no direct table DML**.
Each procedure performs exactly the permitted mutations and nothing else. This is the strongest
option (the app literally cannot issue arbitrary DML) but moves substantial logic into the database
and complicates the JPA/transaction model — a significant refactor.

## Credential storage & rotation
- `audit_app` / `audit_owner` passwords come from the environment / a secret manager (never
  committed), consistent with the current secrets posture.
- Rotation is an operational procedure (rotate in the secret manager; roll the app); no runtime
  in-app rotation is proposed here.

## Why implementation is deferred
- It is **not required** to demonstrate tamper-evidence (the hash chain already detects any mutation;
  this is defense-in-depth against the DB-privilege threat, which the threat model records as a
  residual risk).
- The column-scoped grants + triggers, or the `SECURITY DEFINER` refactor, are a meaningful change to
  migrations, the compose/role setup, and the Testcontainers wiring, with real risk of breaking the
  legitimate redaction/archival flows if the exceptions are not exactly right.
- The single-role prototype keeps the assignment focused on the cryptographic integrity design.

## Migration & testing approach for future implementation
1. **V4 migration:** create `audit_app`; `REVOKE ALL` then `GRANT` the minimal set above; add the
   `BEFORE UPDATE/DELETE` integrity triggers; (optionally) create the `SECURITY DEFINER` procedures.
2. **Runtime:** point the app's datasource at `audit_app`; keep Flyway running as `audit_owner`.
3. **Tests (Testcontainers):**
   - append/redaction/archival still succeed as `audit_app`;
   - a direct `UPDATE audit_event SET content_hash = ...` as `audit_app` is **rejected** (privilege
     or trigger);
   - a direct `DELETE FROM audit_amendment` as `audit_app` is **rejected**;
   - redaction's payload null transition is **allowed**; archival's `audit_event` DELETE is allowed;
   - verify still passes end-to-end.
4. **Rollout:** the change is additive at the DB level; the app only needs a different connection
   role, so it can be staged behind the migration.

## Relationship to other decisions
- Complements ADR 0002 (schema/CHECK constraints) and the threat model's "direct DB tamper" and
  "whole-chain rewrite" rows — this ADR reduces the blast radius of a compromised app credential but
  does **not** by itself defeat an attacker with the `audit_owner` credential (external notarization,
  per the threat model, addresses wholesale rewrite).

## Engineer sign-off
Reviewed and approved by Raghavendra Begur Rangaramu on 2026-08-19.
