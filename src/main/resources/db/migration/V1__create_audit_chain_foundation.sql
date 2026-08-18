-- =============================================================================
-- V1 — Audit chain foundation
--
-- Creates the two foundational tables for the tamper-evident audit log:
--   * audit_event      — the append-only, hash-chained event records
--   * audit_chain_head — a singleton row tracking the current chain tip
--
-- This migration creates SCHEMA ONLY (tables, constraints, indexes) plus one
-- seeded empty-chain head row. No application logic, hashing, or business
-- behavior is implemented here — those live in later steps.
--
-- Hash design (see docs/decisions/0002-audit-chain-schema.md and ADR 0001):
--   * Hashes are SHA-256 → stored as BYTEA of EXACTLY 32 bytes.
--   * previous_hash links each record to its predecessor; content_hash is the
--     record's own hash. The genesis record (sequence_number = 1) has a NULL
--     previous_hash; every later record must carry a 32-byte previous_hash.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- audit_event — append-only, hash-chained event records
-- -----------------------------------------------------------------------------
CREATE TABLE audit_event (
    -- Internal surrogate PK (DB-generated). NOT the public identifier and NOT the
    -- chain ordering key; kept separate so public/business keys are never reused
    -- as storage internals.
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- Public, externally-visible event identifier (opaque UUID). Unique.
    event_id            UUID        NOT NULL,

    -- Monotonic chain position. Unique, strictly positive. The hash chain is
    -- ordered by this column; sequence 1 is the genesis record.
    sequence_number     BIGINT      NOT NULL,

    -- Who / what caused the event.
    actor_id            VARCHAR(255) NOT NULL,
    actor_type          VARCHAR(64)  NOT NULL,

    -- What happened (e.g. USER_LOGIN, RECORD_UPDATED, PERMISSION_GRANTED).
    action              VARCHAR(128) NOT NULL,

    -- The resource affected.
    resource_type       VARCHAR(128) NOT NULL,
    resource_id         VARCHAR(255) NOT NULL,

    -- Result of the action (e.g. SUCCESS, DENIED, FAILURE). Free-form here;
    -- application-level validation is added with the write API in a later step.
    outcome             VARCHAR(64)  NOT NULL,

    -- Optional business justification for the action (e.g. why an account was viewed).
    business_reason     VARCHAR(1024),

    -- When the business event actually occurred (caller-supplied).
    event_timestamp     TIMESTAMPTZ  NOT NULL,

    -- When the audit service ingested/recorded it (server-assigned). Defaulted at
    -- the DB layer as a safety net; the application will set it explicitly.
    recorded_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Version of the canonical hashing/serialization scheme used for this record,
    -- so the verifier can evolve the scheme without ambiguity. Strictly positive.
    schema_version      INTEGER      NOT NULL DEFAULT 1,

    -- Structured, event-specific detail.
    payload             JSONB        NOT NULL DEFAULT '{}'::jsonb,

    -- Hash of the immediately preceding record (NULL only for the genesis record).
    previous_hash       BYTEA,

    -- SHA-256 of this record's canonical content. Always present.
    content_hash        BYTEA        NOT NULL,

    -- ---- Uniqueness constraints ----
    -- Public event id must be unique.
    CONSTRAINT uq_audit_event_event_id       UNIQUE (event_id),
    -- Chain position must be unique (no two records share a sequence number).
    CONSTRAINT uq_audit_event_sequence_number UNIQUE (sequence_number),
    -- NOTE: content_hash is intentionally NOT unique — legitimately identical
    -- event content at different chain positions can collide on content-of-fields;
    -- uniqueness of the *record* is guaranteed by sequence_number + the chain.

    -- ---- Value constraints ----
    CONSTRAINT ck_audit_event_sequence_positive
        CHECK (sequence_number > 0),
    CONSTRAINT ck_audit_event_schema_version_positive
        CHECK (schema_version > 0),

    -- SHA-256 hashes must be exactly 32 bytes.
    CONSTRAINT ck_audit_event_content_hash_len
        CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_audit_event_previous_hash_len
        CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),

    -- Chain linkage rule:
    --   * genesis (sequence_number = 1) MUST have NULL previous_hash;
    --   * every later record MUST have a (32-byte) previous_hash.
    -- The 32-byte length is enforced by ck_audit_event_previous_hash_len above;
    -- here we enforce presence/absence relative to the sequence position.
    CONSTRAINT ck_audit_event_genesis_prev_hash
        CHECK (
            (sequence_number = 1 AND previous_hash IS NULL)
            OR
            (sequence_number > 1 AND previous_hash IS NOT NULL)
        )
);

COMMENT ON TABLE  audit_event IS
    'Append-only, SHA-256 hash-chained audit records. No UPDATE/DELETE is exposed by the API.';
COMMENT ON COLUMN audit_event.sequence_number IS
    'Monotonic chain position (unique, >0). Genesis = 1. Chain is ordered by this column.';
COMMENT ON COLUMN audit_event.previous_hash IS
    'SHA-256 (32 bytes) of the preceding record; NULL only for the genesis record (sequence_number = 1).';
COMMENT ON COLUMN audit_event.content_hash IS
    'SHA-256 (32 bytes) of this record''s canonical content. Not unique.';
COMMENT ON COLUMN audit_event.event_timestamp IS
    'When the business event occurred (caller-supplied).';
COMMENT ON COLUMN audit_event.recorded_at IS
    'When the audit service ingested the event (server-assigned).';
COMMENT ON COLUMN audit_event.schema_version IS
    'Version of the canonical hashing/serialization scheme (>0).';

-- -----------------------------------------------------------------------------
-- Indexes — only those justified by the required query patterns (Scenario A).
--   * by event time (time-range queries);
--   * by actor over time (actor filter + time range);
--   * by resource over time (resource filter + time range).
-- No index on content_hash (not a query dimension) or previous_hash.
-- -----------------------------------------------------------------------------
CREATE INDEX ix_audit_event_event_timestamp
    ON audit_event (event_timestamp);

CREATE INDEX ix_audit_event_actor_time
    ON audit_event (actor_id, event_timestamp);

CREATE INDEX ix_audit_event_resource_time
    ON audit_event (resource_type, resource_id, event_timestamp);

-- -----------------------------------------------------------------------------
-- audit_chain_head — SINGLETON row tracking the current chain tip.
--
-- The append service will (in a later step) lock this row with
-- SELECT ... FOR UPDATE inside the append transaction to serialize writes and
-- guarantee a single deterministic chain. This migration only creates the table
-- and seeds the one empty-chain row.
--
-- Singleton invariant: the primary key is pinned to the constant value 1 via a
-- CHECK, so at most one row can ever exist.
-- -----------------------------------------------------------------------------
CREATE TABLE audit_chain_head (
    -- Pinned to 1 — enforces the singleton invariant together with the CHECK below.
    id               SMALLINT    NOT NULL PRIMARY KEY,

    -- Sequence number of the current chain tip. 0 means "empty chain".
    current_sequence BIGINT      NOT NULL,

    -- content_hash of the current chain tip; NULL while the chain is empty.
    current_hash     BYTEA,

    -- Bookkeeping: last time the head row was advanced.
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Singleton: only id = 1 is permitted.
    CONSTRAINT ck_audit_chain_head_singleton
        CHECK (id = 1),

    -- current_sequence may not be negative (0 = empty chain).
    CONSTRAINT ck_audit_chain_head_sequence_nonneg
        CHECK (current_sequence >= 0),

    -- current_hash, when present, must be a 32-byte SHA-256.
    CONSTRAINT ck_audit_chain_head_hash_len
        CHECK (current_hash IS NULL OR octet_length(current_hash) = 32),

    -- Empty-chain vs non-empty invariant:
    --   * current_sequence = 0  <=> current_hash IS NULL (empty chain);
    --   * current_sequence > 0  requires a 32-byte current_hash.
    CONSTRAINT ck_audit_chain_head_empty_consistency
        CHECK (
            (current_sequence = 0 AND current_hash IS NULL)
            OR
            (current_sequence > 0 AND current_hash IS NOT NULL)
        )
);

COMMENT ON TABLE  audit_chain_head IS
    'Singleton (id=1) row tracking the current audit chain tip. The append service locks this row with SELECT ... FOR UPDATE to serialize appends and keep a single deterministic chain.';
COMMENT ON COLUMN audit_chain_head.current_sequence IS
    'Sequence number of the current chain tip; 0 = empty chain.';
COMMENT ON COLUMN audit_chain_head.current_hash IS
    'content_hash (32 bytes) of the current tip; NULL only while the chain is empty.';

-- Seed exactly one empty-chain head row.
INSERT INTO audit_chain_head (id, current_sequence, current_hash)
VALUES (1, 0, NULL);
