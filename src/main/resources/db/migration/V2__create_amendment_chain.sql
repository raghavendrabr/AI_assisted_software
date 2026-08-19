-- =============================================================================
-- V2 — Amendment chain (for redaction; later also archival)
--
-- Adds a SECOND, independently hash-chained log: audit_amendment. Lifecycle
-- changes (redaction now; archival later) are recorded as append-only amendment
-- records rather than by mutating base events. This makes an authorized redaction
-- a positive, provable fact and keeps lifecycle state inside integrity protection.
--
-- The base audit_event rows remain immutable EXCEPT that a declared-redactable
-- payload field's plaintext `value` may transition present -> null on an
-- authorized redaction. That `value` is excluded from content_hash by design (the
-- hash commits to the field's {salt, commitment}), so redaction never breaks the
-- event chain. See docs/decisions/0003 and the new ADR 0007.
--
-- Amendment chain genesis convention mirrors the event chain (ADR 0002/0003):
--   * amendment_seq 1 has NULL previous_amendment_hash;
--   * later amendments carry the prior amendment's 32-byte content_hash.
-- The singleton audit_chain_head row is extended with the amendment tip.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- audit_amendment — immutable, hash-chained lifecycle records
-- -----------------------------------------------------------------------------
CREATE TABLE audit_amendment (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    amendment_id            UUID        NOT NULL,

    -- Monotonic position in the amendment chain (unique, strictly positive).
    amendment_seq           BIGINT      NOT NULL,

    -- Operation. For now only REDACTION; ARCHIVE is added with retention later.
    operation               VARCHAR(32) NOT NULL,

    -- Target base event. Nullable, NO physical FK: archival will move base rows
    -- between tables, so a FK to audit_event alone would be wrong (ADR 0004 note).
    -- REDACTION requires it; other ops (future ARCHIVE) may leave it null.
    target_sequence_number  BIGINT,

    -- Operation-specific detail (canonical JSON, e.g. {"field":"accountNumber"}).
    detail                  JSONB       NOT NULL DEFAULT '{}'::jsonb,

    -- Who authorized the amendment.
    actor_id                VARCHAR(255) NOT NULL,

    -- When the amendment was recorded (server-assigned, UTC).
    recorded_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Version of the canonical hashing scheme for amendments.
    schema_version          INTEGER     NOT NULL DEFAULT 1,

    -- Hash of the preceding amendment (NULL only for amendment_seq = 1).
    previous_amendment_hash BYTEA,

    -- SHA-256 of this amendment's canonical content. Always present, 32 bytes.
    content_hash            BYTEA       NOT NULL,

    CONSTRAINT uq_audit_amendment_amendment_id  UNIQUE (amendment_id),
    CONSTRAINT uq_audit_amendment_seq           UNIQUE (amendment_seq),

    CONSTRAINT ck_audit_amendment_seq_positive
        CHECK (amendment_seq > 0),
    CONSTRAINT ck_audit_amendment_schema_version_positive
        CHECK (schema_version > 0),
    CONSTRAINT ck_audit_amendment_content_hash_len
        CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_audit_amendment_prev_hash_len
        CHECK (previous_amendment_hash IS NULL OR octet_length(previous_amendment_hash) = 32),

    -- Genesis linkage: amendment_seq 1 => null prev; later => 32-byte prev present.
    CONSTRAINT ck_audit_amendment_genesis_prev_hash
        CHECK (
            (amendment_seq = 1 AND previous_amendment_hash IS NULL)
            OR
            (amendment_seq > 1 AND previous_amendment_hash IS NOT NULL)
        ),

    -- Operation-specific required fields:
    --   REDACTION requires a target_sequence_number.
    CONSTRAINT ck_audit_amendment_redaction_target
        CHECK (operation <> 'REDACTION' OR target_sequence_number IS NOT NULL)
);

COMMENT ON TABLE  audit_amendment IS
    'Append-only, independently hash-chained lifecycle records (redaction; later archival). Never mutated.';
COMMENT ON COLUMN audit_amendment.target_sequence_number IS
    'Base event sequence this amendment targets. Nullable, no physical FK (archival moves base rows between tables).';
COMMENT ON COLUMN audit_amendment.previous_amendment_hash IS
    'SHA-256 (32 bytes) of the preceding amendment; NULL only for amendment_seq = 1.';

CREATE INDEX ix_audit_amendment_target
    ON audit_amendment (target_sequence_number);

-- -----------------------------------------------------------------------------
-- Extend the singleton chain head with the amendment-chain tip.
-- -----------------------------------------------------------------------------
ALTER TABLE audit_chain_head
    ADD COLUMN last_amendment_seq  BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN amendment_head_hash BYTEA;

COMMENT ON COLUMN audit_chain_head.last_amendment_seq IS
    'amendment_seq of the current amendment-chain tip; 0 = no amendments yet.';
COMMENT ON COLUMN audit_chain_head.amendment_head_hash IS
    'content_hash (32 bytes) of the current amendment tip; NULL only while no amendments exist.';

ALTER TABLE audit_chain_head
    ADD CONSTRAINT ck_audit_chain_head_amendment_seq_nonneg
        CHECK (last_amendment_seq >= 0),
    ADD CONSTRAINT ck_audit_chain_head_amendment_hash_len
        CHECK (amendment_head_hash IS NULL OR octet_length(amendment_head_hash) = 32),
    ADD CONSTRAINT ck_audit_chain_head_amendment_empty_consistency
        CHECK (
            (last_amendment_seq = 0 AND amendment_head_hash IS NULL)
            OR
            (last_amendment_seq > 0 AND amendment_head_hash IS NOT NULL)
        );
