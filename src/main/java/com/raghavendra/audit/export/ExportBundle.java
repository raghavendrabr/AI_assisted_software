package com.raghavendra.audit.export;

import java.util.List;

/**
 * A self-contained, independently-verifiable export bundle.
 *
 * <p>{@code manifest} is the canonical, signed description of the export; {@code signature} is its
 * Ed25519 signature (base64) over {@code SHA-256(canonical(manifest))}; {@code publicKeyBase64}
 * lets a recipient verify without prior key exchange (for the dev key). {@code events} and
 * {@code amendments} carry the actual records so the recipient can recompute their hashes.
 */
public record ExportBundle(
        Manifest manifest,
        List<ExportedEvent> events,
        List<ExportedAmendment> amendments,
        String signatureBase64,
        String publicKeyBase64
) {

    /** The signed manifest. Field order here is the canonical order used for the digest. */
    public record Manifest(
            String exportId,
            String exportedAt,
            String filterType,      // "resourceId" or "actorId"
            String filterValue,
            int recordCount,
            List<String> eventHashes,      // ordered content_hash (hex) of exported events
            List<String> amendmentHashes,  // content_hash (hex) of amendments touching exported events
            ChainHeadSnapshot chainHead,
            String signingKeyId
    ) {
    }

    public record ChainHeadSnapshot(
            long lastEventSequence,
            String eventHeadHash,       // hex or null
            long lastAmendmentSeq,
            String amendmentHeadHash    // hex or null
    ) {
    }

    /** An exported event with the fields needed to recompute its content hash. */
    public record ExportedEvent(
            long sequenceNumber,
            String eventId,
            int schemaVersion,
            String actorId,
            String actorType,
            String action,
            String resourceType,
            String resourceId,
            String outcome,
            String businessReason,
            String eventTimestamp,   // ISO-8601 UTC
            String recordedAt,       // ISO-8601 UTC
            String payload,          // raw stored JSON (redactable envelopes as-is)
            String previousHash,     // hex or null
            String contentHash,      // hex
            boolean archived
    ) {
    }

    /** An exported amendment (redaction/archive) touching an exported event. */
    public record ExportedAmendment(
            long amendmentSeq,
            String amendmentId,
            int schemaVersion,
            String operation,
            Long targetSequenceNumber,
            String detail,
            String actorId,
            String recordedAt,
            String previousAmendmentHash,  // hex or null
            String contentHash             // hex
    ) {
    }
}
