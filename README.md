# Tamper-Evident Audit Log Service

> **Project status: REQUIREMENTS & DESIGN STAGE.**
> No application code, database migrations, Docker configuration, or tests exist yet.
> This repository currently contains requirement analysis, assumptions, the AI-usage
> log, and design documentation only. The sections below describe the **intended**
> stack and **planned** capabilities — nothing here is runnable yet, and no tests
> are passing because none have been written.

A service that records an **append-only** history of events and makes any modification
or deletion of past records **detectable** via a cryptographic hash chain. Built as an
interview assignment demonstrating AI-assisted engineering with the engineer owning
correctness, design, and authorship.

---

## Current stage

| Stage | State |
|---|---|
| Requirement analysis & assumptions | In progress (this commit) |
| Design & decision records | Documented in `docs/` and the approved plan |
| Application implementation | **Not started** |
| Tests | **Not started** |
| Runnable end-to-end | **Not yet** |

Run instructions, API examples, and test-status badges will be added **only once the
corresponding code exists**. They are intentionally omitted now to avoid implying
functionality that has not been built.

---

## Intended stack (planned, not yet present)

- **Language / runtime:** Java 21
- **Framework:** Spring Boot 4.1.x (current stable GA line; see `docs/assumptions.md` for the version rationale)
- **Build:** Maven
- **Persistence:** PostgreSQL 16 + Spring Data JPA, schema managed by Flyway migrations
- **API docs:** springdoc-openapi 3.1.x (the springdoc line that supports Spring Boot 4.x)
- **Hashing:** SHA-256 over a canonical serialization of event fields
- **Export signing:** Ed25519 (dedicated signing key, separate from API auth)
- **Testing:** JUnit 5, Mockito, Testcontainers (real PostgreSQL)
- **Local orchestration:** Docker Compose (planned)

> Exact dependency versions will be pinned in `pom.xml` when the project is scaffolded,
> and the choices recorded in an Architecture Decision Record.

---

## Planned capabilities

These map to the three assignment scenarios. **None are implemented yet.**

### Scenario A — Core audit log service
- Write API to append event records (`eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, `timestamp`). Append-only: no update or delete API.
- Query API with filtering (`actorId`, `resourceType` + `resourceId`, `eventType`, time range) and pagination.
- Hash-chain tamper evidence: each record carries a hash of its own content and of the preceding record.
- `GET /audit/verify` endpoint that walks the full chain and reports whether it is intact, and if broken, the first inconsistency and violation type.

### Scenario B — Retention & redaction (extension)
- Configurable retention: old records archivable/soft-deletable without producing false-positive chain breaks.
- Structured payload redaction of sensitive fields without invalidating the hash chain.
- Verifiable bulk export bundle a recipient can independently verify.

### Scenario C — Compliance reporting (ambiguous requirement)
- Clarification and normalization of "regulators need to be able to audit access to client account data," followed by a concrete design and a scoped partial implementation.

---

## Repository layout (current)

```
.
├── README.md                     <- this file
├── ATTESTATION.md                <- authorship attestation (placeholders to be completed)
├── .gitignore
└── docs/
    ├── requirements/
    │   ├── scenario-a.md          <- assignment requirements vs. our assumptions (A)
    │   ├── scenario-b.md          <- assignment requirements vs. our assumptions (B)
    │   └── scenario-c.md          <- ambiguous requirement clarification (C)
    ├── assumptions.md             <- cross-cutting assumptions & open questions
    ├── ai-usage-log.md            <- honest record of AI use in planning/design
    └── final-engineering-summary.md  <- outline, to be filled in as work proceeds
```

The full approved implementation plan (schemas, hash inputs, redaction scheme, archive
verification, export proof format, authorization matrix, commit sequence) lives outside
this repo in the planning workspace and will be reflected here as `docs/architecture.md`
and ADRs under `docs/decisions/` when implementation begins.

---

## Authorship & AI use

This is individual work. AI assistants were used for planning, drafting, and design
review; the engineer directs the work, reviews every output, and owns correctness and
authorship. See `docs/ai-usage-log.md` for an honest, itemized record of what AI
proposed, what was accepted, modified, or rejected, and why. See `ATTESTATION.md` for
the formal attestation.
