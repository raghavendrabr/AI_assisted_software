# Scenario C — Ambiguous: Compliance Reporting

> **Status: requirement analysis only.** Nothing described here is implemented yet.
> This scenario is deliberately under-specified by the assignment. The point is to show
> how we clarify and normalize it **before** writing code.

## C.1 The requirement as given

Product says, verbatim:

> "Regulators need to be able to audit access to client account data."

The assignment asks us to demonstrate:
- how we clarify and normalize the requirement before writing any code;
- what ambiguities we identified and what assumptions we made (or questions we would ask);
- how we translate the clarified requirement into a concrete technical design;
- what we chose to implement versus scoped out, and why.

The submission must include the **clarified requirement statement** we worked from, the
**design decisions** it produced, and an implementation (or a well-reasoned partial
implementation with a documented scope boundary).

## C.2 Ambiguities identified

The one-line request leaves the following genuinely open:

1. **"Access"** — read-only views? Also exports/downloads? Also failed/denied attempts? Also writes/modifications to account data?
2. **"Client account data"** — which resource types count? Is it a specific `resourceType` (e.g. `CLIENT_ACCOUNT`) or a broader set?
3. **"Regulators"** — are they direct API consumers, or do internal compliance staff produce reports *for* regulators? (Changes auth and delivery.)
4. **Report content** — what must each entry show: who, which account, when, how (channel), business purpose, success/failure?
5. **Time scope & timezone** — arbitrary ranges? A regulator-facing canonical timezone (UTC)?
6. **Verifiability** — must the regulator be able to verify the report was not altered (i.e. tie back to the tamper-evident chain)?
7. **Delivery & format** — JSON? CSV? PDF? Signed? Delivered how?
8. **Retention/completeness guarantees** — must the report assert completeness over a period, or just return matching records?
9. **Service-to-service access** — are automated/system accesses in scope or only human actors?
10. **Sensitivity of identifiers** — are employee ids / client ids themselves sensitive and subject to redaction in the report?

## C.3 Assumptions made (to proceed without blocking)

Absent stakeholder answers, we will proceed on these **assumptions** (clearly ours, not
mandates):

- **Access** = any recorded event whose `resourceType` denotes client account data, including **both successful and denied** access, distinguished by a payload field (e.g. `outcome`). Writes are included if they are recorded as such events.
- **Client account data** = events with `resourceType = CLIENT_ACCOUNT` (configurable set).
- **Consumer** = an authorized internal **compliance reader** produces reports; regulator-facing identity federation is out of scope.
- **Each entry shows** who (`actorId`), which account (`resourceId`), when (`eventTimestamp` + `recordedAt`), how (channel from payload), purpose (payload), and outcome.
- **Timezone** = UTC in the report; callers may filter by an arbitrary range.
- **Verifiability** = the report is tied to the audit chain and can be exported as a verifiable bundle (reusing Scenario B's Ed25519-signed export).
- **Format** = JSON (verifiable); PDF/scheduled/delivered reports are out of scope.
- **Service accesses** = included if recorded as events with an `actorId`.

## C.4 Clarified requirement statement (what we will build to)

> Authorized compliance users must be able to retrieve and export an **immutable,
> independently verifiable** report of access to client-account data — including both
> **successful and denied** access — filterable by actor, account (`resourceId`),
> access outcome, and time range. Each report entry must identify **who** accessed
> **which** account, **when**, **how** (channel), its **business purpose**, and
> **whether it succeeded**. The report must be tie-able back to the tamper-evident audit
> chain so a recipient can confirm it was not altered.

## C.5 Design translation (planned)

- A read endpoint `GET /compliance/access-report` filtering the existing audit events by
  the client-account resource type plus actor / account / outcome / time-range.
- Report entries are projections over stored events (no new source of truth).
- Verifiability reuses the Scenario B Ed25519-signed export bundle so the report can be
  independently checked against the chain.
- Authorization: `COMPLIANCE_READER` role (see the authorization matrix in the plan).

## C.6 What we will implement vs. scope out

**Planned to implement:** the query + JSON report over the in-scope slice
(successful + denied access to `CLIENT_ACCOUNT`), with verifiable export.

**Explicitly scoped out (documented boundaries):** regulator identity federation /
direct regulator login; scheduled report generation; PDF rendering; external delivery
(email/SFTP); statistical completeness attestations over a period beyond what the signed
bundle already provides.

> None of the above is implemented in this commit. This document is the clarified
> requirement and design intent; the implementation follows on Day 3 of the plan.
