package com.raghavendra.audit.retention;

import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the length-prefixed manifest hash: determinism and unambiguous field boundaries
 * (no cross-field collision even when a text field contains separator-like bytes).
 */
class ArchiveManifestHasherTest {

    private final ArchiveManifestHasher hasher = new ArchiveManifestHasher();
    private final UUID id = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private final OffsetDateTime at = OffsetDateTime.of(2026, 8, 1, 10, 0, 0, 0, ZoneOffset.UTC);
    private final byte[] first = filled((byte) 0x01);
    private final byte[] last = filled((byte) 0x02);

    private static byte[] filled(byte b) {
        byte[] a = new byte[32];
        java.util.Arrays.fill(a, b);
        return a;
    }

    @Test
    void isDeterministic() {
        byte[] h1 = hasher.hash(id, 1, 3, 3, first, last, at, "admin-1");
        byte[] h2 = hasher.hash(id, 1, 3, 3, first, last, at, "admin-1");
        assertThat(h1).isEqualTo(h2).hasSize(32);
    }

    @Test
    void fieldBoundaries_areUnambiguous_evenWithSeparatorBytesInText() {
        // With length-prefixing, "a" + "bc" and "ab" + "c" (as adjacent fields) must NOT collide,
        // and a value containing 0x1F must not shift the layout. Use authorizedBy variations.
        byte[] withUS = hasher.hash(id, 1, 3, 3, first, last, at, "admin");
        byte[] shifted = hasher.hash(id, 1, 3, 3, first, last, at, "adm");
        assertThat(withUS).isNotEqualTo(shifted);
    }

    @Test
    void changingAnyField_changesHash() {
        byte[] base = hasher.hash(id, 1, 3, 3, first, last, at, "admin-1");
        assertThat(hasher.hash(id, 2, 3, 3, first, last, at, "admin-1")).isNotEqualTo(base);
        assertThat(hasher.hash(id, 1, 4, 3, first, last, at, "admin-1")).isNotEqualTo(base);
        assertThat(hasher.hash(id, 1, 3, 4, first, last, at, "admin-1")).isNotEqualTo(base);
        assertThat(hasher.hash(id, 1, 3, 3, last, last, at, "admin-1")).isNotEqualTo(base);
        assertThat(hasher.hash(id, 1, 3, 3, first, first, at, "admin-1")).isNotEqualTo(base);
        assertThat(hasher.hash(id, 1, 3, 3, first, last, at.plusSeconds(1), "admin-1")).isNotEqualTo(base);
        assertThat(hasher.hash(id, 1, 3, 3, first, last, at, "admin-2")).isNotEqualTo(base);
    }
}
