-- =============================================================================
-- V3 — Retention & archival
--
-- Adds archival: old events are MOVED from audit_event into audit_event_archive
-- (never physically destroyed), recorded by an archive_manifest and an ARCHIVE
-- amendment binding that manifest. Verification reads active + archived events as
-- one ordered chain, so archival is not a false break.
--
-- audit_event_archive mirrors audit_event's integrity-relevant columns EXACTLY
-- (sequence numbers, hashes, payloads, timestamps preserved). The archive keeps
-- its own surrogate id; sequence_number stays unique ACROSS active+archive
-- (enforced in the service; sequence values never collide because a sequence is
-- moved, not copied).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- audit_event_archive — archived (moved) base events. Same integrity columns.
-- -----------------------------------------------------------------------------
CREATE TABLE audit_event_archive (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id            UUID        NOT NULL,
    sequence_number     BIGINT      NOT NULL,
    actor_id            VARCHAR(255) NOT NULL,
    actor_type          VARCHAR(64)  NOT NULL,
    action              VARCHAR(128) NOT NULL,
    resource_type       VARCHAR(128) NOT NULL,
    resource_id         VARCHAR(255) NOT NULL,
    outcome             VARCHAR(64)  NOT NULL,
    business_reason     VARCHAR(1024),
    event_timestamp     TIMESTAMPTZ  NOT NULL,
    recorded_at         TIMESTAMPTZ  NOT NULL,
    schema_version      INTEGER      NOT NULL,
    payload             JSONB        NOT NULL,
    previous_hash       BYTEA,
    content_hash        BYTEA        NOT NULL,

    -- When this record was archived (for auditability of the retention action).
    archived_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_audit_event_archive_event_id       UNIQUE (event_id),
    CONSTRAINT uq_audit_event_archive_sequence       UNIQUE (sequence_number),
    CONSTRAINT ck_audit_event_archive_seq_positive   CHECK (sequence_number > 0),
    CONSTRAINT ck_audit_event_archive_schema_version CHECK (schema_version > 0),
    CONSTRAINT ck_audit_event_archive_content_hash_len
        CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_audit_event_archive_prev_hash_len
        CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
    CONSTRAINT ck_audit_event_archive_genesis_prev_hash
        CHECK (
            (sequence_number = 1 AND previous_hash IS NULL)
            OR
            (sequence_number > 1 AND previous_hash IS NOT NULL)
        )
);

COMMENT ON TABLE audit_event_archive IS
    'Archived (moved) base events. Integrity columns preserved exactly; verification reads active UNION archive as one chain.';

CREATE INDEX ix_audit_event_archive_event_ts ON audit_event_archive (event_timestamp);

-- -----------------------------------------------------------------------------
-- archive_manifest — one row per archival operation. Binds the archived range.
-- -----------------------------------------------------------------------------
CREATE TABLE archive_manifest (
    manifest_id     UUID        NOT NULL PRIMARY KEY,
    from_sequence   BIGINT      NOT NULL,
    to_sequence     BIGINT      NOT NULL,
    record_count    BIGINT      NOT NULL,
    first_hash      BYTEA       NOT NULL,
    last_hash       BYTEA       NOT NULL,
    archived_at     TIMESTAMPTZ NOT NULL,
    authorized_by   VARCHAR(255) NOT NULL,

    -- Canonical manifest hash (see ArchiveManifestHasher / ADR 0008), 32 bytes.
    manifest_hash   BYTEA       NOT NULL,

    CONSTRAINT ck_archive_manifest_range        CHECK (from_sequence <= to_sequence),
    CONSTRAINT ck_archive_manifest_count        CHECK (record_count > 0),
    CONSTRAINT ck_archive_manifest_first_len    CHECK (octet_length(first_hash) = 32),
    CONSTRAINT ck_archive_manifest_last_len     CHECK (octet_length(last_hash) = 32),
    CONSTRAINT ck_archive_manifest_hash_len     CHECK (octet_length(manifest_hash) = 32)
);

COMMENT ON TABLE archive_manifest IS
    'One row per archival operation; binds fromSequence/toSequence/recordCount/first_hash/last_hash under manifest_hash. An ARCHIVE amendment binds manifest_hash into the amendment chain.';
