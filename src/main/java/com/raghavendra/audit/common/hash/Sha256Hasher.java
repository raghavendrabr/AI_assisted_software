package com.raghavendra.audit.common.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 hashing over the canonical form of a {@link ProtectedEventProjection}.
 *
 * <p>The content hash of an event is defined as:
 * <pre>
 *   content_hash = SHA-256( UTF-8( CanonicalJsonSerializer.canonicalize(projection) ) )
 * </pre>
 * i.e. the SHA-256 digest of the UTF-8 bytes of the canonical string. The result is exactly
 * 32 bytes, matching the {@code BYTEA} 32-byte constraint enforced by the V1 schema.
 *
 * <p><strong>Genesis convention (no genesis hash).</strong> There is deliberately no
 * "genesis hash" sentinel. The first event has {@code sequenceNumber = 1} and
 * {@code previousHash = null}; its canonical projection therefore contains
 * {@code "previousHash":null}. Later events carry the previous event's 32-byte content hash
 * (rendered as 64-char lowercase hex in the canonical form). The empty chain head is
 * {@code sequence 0, current_hash null}. This matches the V1 schema (ADR 0002) exactly.
 * This class performs no chaining itself.
 */
public final class Sha256Hasher {

    private final CanonicalJsonSerializer serializer;

    public Sha256Hasher(CanonicalJsonSerializer serializer) {
        this.serializer = serializer;
    }

    /**
     * Compute the 32-byte SHA-256 content hash of the protected projection.
     *
     * @param projection the protected projection
     * @return a new 32-byte array containing the digest
     */
    public byte[] contentHash(ProtectedEventProjection projection) {
        String canonical = serializer.canonicalize(projection);
        return sha256(canonical.getBytes(StandardCharsets.UTF_8));
    }

    /** The 32-byte SHA-256 content hash of an amendment projection. */
    public byte[] amendmentContentHash(ProtectedAmendmentProjection projection) {
        String canonical = serializer.canonicalizeAmendment(projection);
        return sha256(canonical.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Convenience overload used by tests and lower-level callers: SHA-256 of an arbitrary
     * canonical string's UTF-8 bytes.
     */
    public byte[] hashCanonicalString(String canonical) {
        return sha256(canonical.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] sha256(byte[] input) {
        try {
            // MessageDigest is not thread-safe; a fresh instance per call keeps this class stateless.
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JLS for every JVM; this cannot happen in practice.
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
