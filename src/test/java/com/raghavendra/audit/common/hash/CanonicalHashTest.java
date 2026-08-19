package com.raghavendra.audit.common.hash;

import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests (no Spring, no DB) proving the determinism and integrity properties of the
 * canonical serializer and SHA-256 hasher.
 *
 * <p>Properties covered:
 * <ol>
 *   <li>determinism (same input → same hash, repeatedly);</li>
 *   <li>field-order independence (top-level field order is fixed by the projection);</li>
 *   <li>payload-key-order independence (object keys are sorted);</li>
 *   <li>UTF-8 behavior (non-ASCII characters hash stably and distinctly);</li>
 *   <li>null handling (null protected field ≠ empty string, and is emitted explicitly);</li>
 *   <li>timestamp normalization (equal instants in different offsets canonicalize equally);</li>
 *   <li>sensitivity: changing ANY protected field changes the hash.</li>
 * </ol>
 */
class CanonicalHashTest {

    private final CanonicalJsonSerializer serializer = new CanonicalJsonSerializer();
    private final Sha256Hasher hasher = new Sha256Hasher(serializer);

    private ProtectedEventProjection baseline() {
        return new ProtectedEventProjection(
                1,
                1L,
                "11111111-1111-1111-1111-111111111111",
                "actor-1",
                "USER",
                "USER_LOGIN",
                "CLIENT_ACCOUNT",
                "acct-1",
                "SUCCESS",
                "customer support",
                OffsetDateTime.of(2026, 8, 18, 12, 0, 0, 0, ZoneOffset.UTC),
                OffsetDateTime.of(2026, 8, 18, 12, 0, 1, 0, ZoneOffset.UTC),
                "{\"channel\":\"WEB\",\"amount\":100}",
                null
        );
    }

    // ---- 1. Determinism ----------------------------------------------------------------

    @Test
    void hash_isDeterministic_acrossRepeatedCalls() {
        ProtectedEventProjection p = baseline();
        byte[] h1 = hasher.contentHash(p);
        byte[] h2 = hasher.contentHash(p);
        assertThat(h1).isEqualTo(h2);
        assertThat(h1).hasSize(32); // SHA-256 = 32 bytes
    }

    @Test
    void canonicalString_isStable() {
        assertThat(serializer.canonicalize(baseline()))
                .isEqualTo(serializer.canonicalize(baseline()));
    }

    // ---- 2. Field-order independence (top-level order is fixed by the record) ----------

    @Test
    void topLevelFieldOrder_isFixedAndNotAlphabetical() {
        // The canonical form must emit fields in the projection's declared order,
        // NOT alphabetical, and always the same way.
        String canonical = serializer.canonicalize(baseline());
        assertThat(canonical.indexOf("\"schemaVersion\""))
                .isLessThan(canonical.indexOf("\"sequenceNumber\""));
        assertThat(canonical.indexOf("\"eventId\""))
                .isLessThan(canonical.indexOf("\"actorId\""));
        assertThat(canonical.indexOf("\"payload\""))
                .isLessThan(canonical.indexOf("\"previousHash\""));
    }

    // ---- 3. Payload key-order independence ---------------------------------------------

    @Test
    void payloadKeyOrder_doesNotAffectHash() {
        ProtectedEventProjection a = withPayload("{\"channel\":\"WEB\",\"amount\":100}");
        ProtectedEventProjection b = withPayload("{\"amount\":100,\"channel\":\"WEB\"}");
        assertThat(hasher.contentHash(a)).isEqualTo(hasher.contentHash(b));
    }

    @Test
    void nestedPayloadKeyOrder_doesNotAffectHash() {
        ProtectedEventProjection a = withPayload("{\"outer\":{\"b\":2,\"a\":1},\"z\":3}");
        ProtectedEventProjection b = withPayload("{\"z\":3,\"outer\":{\"a\":1,\"b\":2}}");
        assertThat(hasher.contentHash(a)).isEqualTo(hasher.contentHash(b));
    }

    @Test
    void payloadArrayOrder_DOES_affectHash() {
        // Arrays are ordered by definition — different order is a different value.
        ProtectedEventProjection a = withPayload("{\"items\":[1,2,3]}");
        ProtectedEventProjection b = withPayload("{\"items\":[3,2,1]}");
        assertThat(hasher.contentHash(a)).isNotEqualTo(hasher.contentHash(b));
    }

    // ---- 4. UTF-8 behavior -------------------------------------------------------------

    @Test
    void utf8Characters_hashStablyAndDistinctly() {
        ProtectedEventProjection accented = withActor("José");
        ProtectedEventProjection plain = withActor("Jose");
        // Stable: same non-ASCII input hashes the same twice.
        assertThat(hasher.contentHash(accented)).isEqualTo(hasher.contentHash(withActor("José")));
        // Distinct: the accented form differs from the plain form.
        assertThat(hasher.contentHash(accented)).isNotEqualTo(hasher.contentHash(plain));
    }

    @Test
    void utf8MultiByteInPayload_isStable() {
        ProtectedEventProjection a = withPayload("{\"note\":\"日本語\"}");
        ProtectedEventProjection b = withPayload("{\"note\":\"日本語\"}");
        assertThat(hasher.contentHash(a)).isEqualTo(hasher.contentHash(b));
    }

    // ---- 5. Null handling --------------------------------------------------------------

    @Test
    void nullField_differsFromEmptyString() {
        ProtectedEventProjection nullReason = withBusinessReason(null);
        ProtectedEventProjection emptyReason = withBusinessReason("");
        assertThat(hasher.contentHash(nullReason)).isNotEqualTo(hasher.contentHash(emptyReason));
    }

    @Test
    void nullField_isEmittedExplicitlyAsNullToken() {
        String canonical = serializer.canonicalize(withBusinessReason(null));
        assertThat(canonical).contains("\"businessReason\":null");
    }

    @Test
    void nullPreviousHash_genesis_isExplicit() {
        String canonical = serializer.canonicalize(baseline()); // previousHash == null
        assertThat(canonical).contains("\"previousHash\":null");
    }

    // ---- 6. Timestamp normalization ----------------------------------------------------

    @Test
    void equalInstantsInDifferentOffsets_canonicalizeEqually() {
        OffsetDateTime utc = OffsetDateTime.of(2026, 8, 18, 12, 0, 0, 0, ZoneOffset.UTC);
        OffsetDateTime plusTwo = utc.withOffsetSameInstant(ZoneOffset.ofHours(2)); // same instant
        ProtectedEventProjection a = withEventTimestamp(utc);
        ProtectedEventProjection b = withEventTimestamp(plusTwo);
        assertThat(hasher.contentHash(a)).isEqualTo(hasher.contentHash(b));
    }

    @Test
    void differentInstants_produceDifferentHash() {
        OffsetDateTime t1 = OffsetDateTime.of(2026, 8, 18, 12, 0, 0, 0, ZoneOffset.UTC);
        OffsetDateTime t2 = t1.plusSeconds(1);
        assertThat(hasher.contentHash(withEventTimestamp(t1)))
                .isNotEqualTo(hasher.contentHash(withEventTimestamp(t2)));
    }

    @Test
    void timestamp_isRenderedInUtcWithZ_sixFractionalDigits() {
        String canonical = serializer.canonicalize(
                withEventTimestamp(OffsetDateTime.of(2026, 8, 18, 14, 30, 0, 0, ZoneOffset.ofHours(2))));
        // 14:30+02:00 == 12:30Z, and exactly 6 fractional (microsecond) digits.
        assertThat(canonical).contains("2026-08-18T12:30:00.000000Z");
    }

    // ---- 6b. Microsecond (PostgreSQL TIMESTAMPTZ) precision -----------------------------

    @Test
    void subMicrosecondDifferences_normalizeConsistently_sameHash() {
        // Two instants that differ ONLY in nanoseconds below the microsecond floor: Postgres
        // cannot preserve this difference, so canonicalization must collapse them together.
        OffsetDateTime a = OffsetDateTime.of(2026, 8, 18, 12, 0, 0, 123_456_000, ZoneOffset.UTC);
        OffsetDateTime b = OffsetDateTime.of(2026, 8, 18, 12, 0, 0, 123_456_789, ZoneOffset.UTC);
        assertThat(hasher.contentHash(withEventTimestamp(a)))
                .isEqualTo(hasher.contentHash(withEventTimestamp(b)));
    }

    @Test
    void microsecondLevelDifference_changesHash() {
        OffsetDateTime a = OffsetDateTime.of(2026, 8, 18, 12, 0, 0, 123_456_000, ZoneOffset.UTC);
        OffsetDateTime b = OffsetDateTime.of(2026, 8, 18, 12, 0, 0, 123_457_000, ZoneOffset.UTC); // +1 microsecond
        assertThat(hasher.contentHash(withEventTimestamp(a)))
                .isNotEqualTo(hasher.contentHash(withEventTimestamp(b)));
    }

    @Test
    void rereadingAPostgresPersistedTimestamp_doesNotChangeCanonicalForm() {
        // Simulate the persist/reread round-trip: PostgreSQL TIMESTAMPTZ keeps microseconds.
        // A value hashed at nanosecond input must canonicalize identically to the same value
        // after it has been truncated to microseconds (what comes back from the DB).
        OffsetDateTime beforePersist = OffsetDateTime.of(2026, 8, 18, 12, 0, 0, 123_456_789, ZoneOffset.UTC);
        OffsetDateTime afterReread = beforePersist.truncatedTo(java.time.temporal.ChronoUnit.MICROS);
        assertThat(serializer.canonicalize(withEventTimestamp(beforePersist)))
                .isEqualTo(serializer.canonicalize(withEventTimestamp(afterReread)));
        assertThat(hasher.contentHash(withEventTimestamp(beforePersist)))
                .isEqualTo(hasher.contentHash(withEventTimestamp(afterReread)));
    }

    // ---- previousHash encoding ---------------------------------------------------------

    @Test
    void previousHash_isRenderedAs64LowercaseHexChars() {
        byte[] prev = new byte[32];
        for (int i = 0; i < 32; i++) {
            prev[i] = (byte) i; // 00 01 02 ... 1f
        }
        String canonical = serializer.canonicalize(withSeqAndPrev(2L, prev));
        String expectedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assertThat(expectedHex).hasSize(64);
        assertThat(canonical).contains("\"previousHash\":\"" + expectedHex + "\"");
    }

    @Test
    void previousHash_null_isJsonNullToken_forGenesis() {
        String canonical = serializer.canonicalize(baseline()); // genesis: seq 1, prev null
        assertThat(canonical).contains("\"previousHash\":null");
        assertThat(canonical).doesNotContain("\"previousHash\":\"");
    }

    @Test
    void previousHash_hexUsesLowercaseForHighBytes() {
        byte[] prev = new byte[32];
        java.util.Arrays.fill(prev, (byte) 0xAB); // high nibble/letters -> must be lowercase 'ab'
        String canonical = serializer.canonicalize(withSeqAndPrev(2L, prev));
        assertThat(canonical).contains("\"previousHash\":\"" + "ab".repeat(32) + "\"");
    }

    @Test
    void previousHash_isDefensivelyCopied_callerMutationDoesNotAffectHashOrCanonicalForm() {
        byte[] original = hash32Bytes(0x11);
        ProtectedEventProjection p = withSeqAndPrev(2L, original);

        String canonicalBefore = serializer.canonicalize(p);
        byte[] hashBefore = hasher.contentHash(p);

        // Mutate the CALLER'S original array after construction.
        java.util.Arrays.fill(original, (byte) 0x22);

        // The projection must be unaffected (it copied on construction).
        assertThat(serializer.canonicalize(p)).isEqualTo(canonicalBefore);
        assertThat(hasher.contentHash(p)).isEqualTo(hashBefore);

        // And the accessor must not hand back the internal array for external mutation.
        byte[] fromAccessor = p.previousHash();
        java.util.Arrays.fill(fromAccessor, (byte) 0x33);
        assertThat(serializer.canonicalize(p)).isEqualTo(canonicalBefore);
        assertThat(hasher.contentHash(p)).isEqualTo(hashBefore);
    }

    // ---- 7. Sensitivity: changing ANY protected field changes the hash -----------------

    @Test
    void changingAnyProtectedField_changesHash() {
        byte[] base = hasher.contentHash(baseline());
        ProtectedEventProjection b = baseline();

        assertThat(hasher.contentHash(new ProtectedEventProjection(
                2, b.sequenceNumber(), b.eventId(), b.actorId(), b.actorType(), b.action(),
                b.resourceType(), b.resourceId(), b.outcome(), b.businessReason(),
                b.eventTimestamp(), b.recordedAt(), b.payloadJson(), b.previousHash())))
                .as("schemaVersion").isNotEqualTo(base);

        // sequenceNumber sensitivity: compare two VALID non-genesis events (both need a
        // previousHash) that differ only in sequence_number.
        assertThat(hasher.contentHash(withSeqAndPrev(2L, hash32Bytes(0x11))))
                .as("sequenceNumber")
                .isNotEqualTo(hasher.contentHash(withSeqAndPrev(3L, hash32Bytes(0x11))));

        assertThat(hasher.contentHash(withActor("actor-2"))).as("actorId").isNotEqualTo(base);
        assertThat(hasher.contentHash(mutate("actorType", "SYSTEM"))).as("actorType").isNotEqualTo(base);
        assertThat(hasher.contentHash(mutate("action", "USER_LOGOUT"))).as("action").isNotEqualTo(base);
        assertThat(hasher.contentHash(mutate("resourceType", "ORDER"))).as("resourceType").isNotEqualTo(base);
        assertThat(hasher.contentHash(mutate("resourceId", "acct-2"))).as("resourceId").isNotEqualTo(base);
        assertThat(hasher.contentHash(mutate("outcome", "DENIED"))).as("outcome").isNotEqualTo(base);
        assertThat(hasher.contentHash(withBusinessReason("other"))).as("businessReason").isNotEqualTo(base);
        assertThat(hasher.contentHash(withPayload("{\"channel\":\"API\",\"amount\":100}")))
                .as("payload").isNotEqualTo(base);

        // previousHash: a genesis (seq 1, null) vs a later event (seq 2, 32-byte hash) differ.
        // (The genesis constraint forbids seq 1 + previousHash, so compare seq-2 variants.)
        ProtectedEventProjection later1 = withSeqAndPrev(2L, hash32Bytes(0xAA));
        ProtectedEventProjection later2 = withSeqAndPrev(2L, hash32Bytes(0xBB));
        assertThat(hasher.contentHash(later1)).as("previousHash")
                .isNotEqualTo(hasher.contentHash(later2));
    }

    // ---- builders ----------------------------------------------------------------------

    private ProtectedEventProjection withPayload(String payloadJson) {
        ProtectedEventProjection b = baseline();
        return new ProtectedEventProjection(b.schemaVersion(), b.sequenceNumber(), b.eventId(),
                b.actorId(), b.actorType(), b.action(), b.resourceType(), b.resourceId(),
                b.outcome(), b.businessReason(), b.eventTimestamp(), b.recordedAt(),
                payloadJson, b.previousHash());
    }

    private ProtectedEventProjection withActor(String actorId) {
        ProtectedEventProjection b = baseline();
        return new ProtectedEventProjection(b.schemaVersion(), b.sequenceNumber(), b.eventId(),
                actorId, b.actorType(), b.action(), b.resourceType(), b.resourceId(),
                b.outcome(), b.businessReason(), b.eventTimestamp(), b.recordedAt(),
                b.payloadJson(), b.previousHash());
    }

    private ProtectedEventProjection withBusinessReason(String reason) {
        ProtectedEventProjection b = baseline();
        return new ProtectedEventProjection(b.schemaVersion(), b.sequenceNumber(), b.eventId(),
                b.actorId(), b.actorType(), b.action(), b.resourceType(), b.resourceId(),
                b.outcome(), reason, b.eventTimestamp(), b.recordedAt(),
                b.payloadJson(), b.previousHash());
    }

    private ProtectedEventProjection withEventTimestamp(OffsetDateTime ts) {
        ProtectedEventProjection b = baseline();
        return new ProtectedEventProjection(b.schemaVersion(), b.sequenceNumber(), b.eventId(),
                b.actorId(), b.actorType(), b.action(), b.resourceType(), b.resourceId(),
                b.outcome(), b.businessReason(), ts, b.recordedAt(),
                b.payloadJson(), b.previousHash());
    }

    private ProtectedEventProjection withSeqAndPrev(long seq, byte[] prev) {
        ProtectedEventProjection b = baseline();
        return new ProtectedEventProjection(b.schemaVersion(), seq, b.eventId(),
                b.actorId(), b.actorType(), b.action(), b.resourceType(), b.resourceId(),
                b.outcome(), b.businessReason(), b.eventTimestamp(), b.recordedAt(),
                b.payloadJson(), prev);
    }

    private static byte[] hash32Bytes(int fill) {
        byte[] b = new byte[32];
        java.util.Arrays.fill(b, (byte) fill);
        return b;
    }

    /** Minimal field-swapper for the string fields exercised in the sensitivity test. */
    private ProtectedEventProjection mutate(String field, String value) {
        ProtectedEventProjection b = baseline();
        return switch (field) {
            case "actorType" -> new ProtectedEventProjection(b.schemaVersion(), b.sequenceNumber(),
                    b.eventId(), b.actorId(), value, b.action(), b.resourceType(), b.resourceId(),
                    b.outcome(), b.businessReason(), b.eventTimestamp(), b.recordedAt(),
                    b.payloadJson(), b.previousHash());
            case "action" -> new ProtectedEventProjection(b.schemaVersion(), b.sequenceNumber(),
                    b.eventId(), b.actorId(), b.actorType(), value, b.resourceType(), b.resourceId(),
                    b.outcome(), b.businessReason(), b.eventTimestamp(), b.recordedAt(),
                    b.payloadJson(), b.previousHash());
            case "resourceType" -> new ProtectedEventProjection(b.schemaVersion(), b.sequenceNumber(),
                    b.eventId(), b.actorId(), b.actorType(), b.action(), value, b.resourceId(),
                    b.outcome(), b.businessReason(), b.eventTimestamp(), b.recordedAt(),
                    b.payloadJson(), b.previousHash());
            case "resourceId" -> new ProtectedEventProjection(b.schemaVersion(), b.sequenceNumber(),
                    b.eventId(), b.actorId(), b.actorType(), b.action(), b.resourceType(), value,
                    b.outcome(), b.businessReason(), b.eventTimestamp(), b.recordedAt(),
                    b.payloadJson(), b.previousHash());
            case "outcome" -> new ProtectedEventProjection(b.schemaVersion(), b.sequenceNumber(),
                    b.eventId(), b.actorId(), b.actorType(), b.action(), b.resourceType(), b.resourceId(),
                    value, b.businessReason(), b.eventTimestamp(), b.recordedAt(),
                    b.payloadJson(), b.previousHash());
            default -> throw new IllegalArgumentException("unhandled field: " + field);
        };
    }
}
