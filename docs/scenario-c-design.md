# Scenario C — Compliance Reporting: Clarification, Design & Implementation

> Companion to `docs/requirements/scenario-c.md` (which captures the ambiguities and assumptions).
> This document is the clarified requirement I worked from, the design it produced, and what was
> implemented vs. scoped out.

## The raw requirement

> Product: *"Regulators need to be able to audit access to client account data."*

Intentionally under-specified. Before writing code I normalized it (below) and recorded the
ambiguities and the questions I would ask a stakeholder (`scenario-c.md` §C.2–C.3).

## Clarified requirement statement (worked from)

> **Authorized compliance users** must be able to retrieve and export an **immutable, independently
> verifiable** report of access to **client-account data** — including both **successful and
> denied** access — filterable by **actor**, **account**, **access outcome**, and **time range**.
> Each entry must identify **who** accessed **which** account, **when**, **how** (the action), the
> **business purpose**, and **whether it succeeded**. The report must tie back to the tamper-evident
> audit chain so a recipient can confirm it was not altered.

## Design decisions produced

1. **No new source of truth.** A compliance report is a *projection* over existing audit events,
   scoped to `resourceType = <client-account type>` (configurable, default `CLIENT_ACCOUNT`). This
   keeps the tamper-evidence guarantees automatically — nothing is re-recorded.
2. **Access = recorded events, success AND denied.** Distinguished by the `outcome` field
   (e.g. `SUCCESS` / `DENIED`), so "who was refused access" is auditable, not just successes.
3. **Filters:** `actorId`, `accountId` (the account `resourceId`), `outcome`, and time range —
   the dimensions a regulator/compliance officer actually queries by.
4. **Tie-back to the chain.** Each entry carries the record's `sequenceNumber` and `contentHash`;
   a recipient can cross-check against `GET /audit/verify` (whole-chain) or a signed export bundle
   (subset). Reports include archived access by default so history isn't silently truncated.
5. **Authorization:** `COMPLIANCE_READER` (or ADMIN) — internal compliance staff produce reports;
   regulator identity federation is out of scope.

## Implemented

`GET /api/v1/compliance/access-report?actorId=&accountId=&outcome=&from=&to=&includeArchived=`
returns entries `{who, whichAccount, when (event + recorded), how (action), why (businessReason),
outcome, sequenceNumber, contentHash, archived}` plus an echo of the applied filters. Reuses the
bounded, cursor-paginated, archive-aware query, so it inherits stable pagination and the size
bound. Covered by `ComplianceReportIntegrationTest` (success + denied, filters, non-client-account
excluded, content-hash tie-back, inverted range → 400) and the archive-boundary test (archived
access appears exactly once).

## Scoped out (documented boundaries)

- **Regulator identity federation / direct regulator login** — reports are produced by internal
  compliance users; giving regulators their own authenticated access is a separate identity project.
- **Scheduled/automated report generation** and **PDF rendering / external delivery** (email/SFTP)
  — presentation/delivery concerns, not core to the audit guarantee.
- **Statistical completeness attestation** over a period beyond what a signed export already
  provides — same completeness limitation as the export (needs the full chain or a Merkle
  accumulator).

## Why this scope

The riskiest, highest-value part of "audit access to client account data" is that the access
records are **complete, immutable, and provably unaltered** — which the core service already
guarantees — and that a compliance user can **query and hand off a verifiable slice**. That is
what I implemented. The scoped-out items are delivery/identity concerns that don't change the
integrity story and would trade depth on the core guarantee for breadth.
