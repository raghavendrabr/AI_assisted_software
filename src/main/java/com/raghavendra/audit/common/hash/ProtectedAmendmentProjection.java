package com.raghavendra.audit.common.hash;

import java.time.OffsetDateTime;
import java.util.Objects;

/**
 * The protected hash projection of an {@code audit_amendment} record: the ordered fields the
 * amendment content hash commits to. Analogous to {@link ProtectedEventProjection} but for the
 * separate amendment chain.
 *
 * @param schemaVersion         canonicalization/hash scheme version (>0)
 * @param amendmentSeq          amendment chain position (>0)
 * @param amendmentId           public amendment UUID (canonical string)
 * @param operation             e.g. REDACTION
 * @param targetSequenceNumber  base event sequence targeted (nullable for some ops)
 * @param detailJson            canonical JSON detail (object keys sorted by the serializer)
 * @param actorId               who authorized the amendment
 * @param recordedAt            server ingestion time (UTC, microsecond-normalized)
 * @param previousAmendmentHash preceding amendment's 32-byte content hash, or null for genesis
 */
public record ProtectedAmendmentProjection(
        int schemaVersion,
        long amendmentSeq,
        String amendmentId,
        String operation,
        Long targetSequenceNumber,
        String detailJson,
        String actorId,
        OffsetDateTime recordedAt,
        byte[] previousAmendmentHash
) {
    public ProtectedAmendmentProjection {
        Objects.requireNonNull(amendmentId, "amendmentId");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(actorId, "actorId");
        if (previousAmendmentHash != null && previousAmendmentHash.length != 32) {
            throw new IllegalArgumentException(
                    "previousAmendmentHash must be null or exactly 32 bytes, was "
                            + previousAmendmentHash.length);
        }
        if (amendmentSeq == 1 && previousAmendmentHash != null) {
            throw new IllegalArgumentException("genesis amendment (seq 1) must have null previousAmendmentHash");
        }
        if (amendmentSeq > 1 && previousAmendmentHash == null) {
            throw new IllegalArgumentException("non-genesis amendment (seq > 1) requires a previousAmendmentHash");
        }
        previousAmendmentHash = previousAmendmentHash == null ? null : previousAmendmentHash.clone();
    }

    @Override
    public byte[] previousAmendmentHash() {
        return previousAmendmentHash == null ? null : previousAmendmentHash.clone();
    }
}
