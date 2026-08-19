package com.raghavendra.audit.export;

import org.junit.jupiter.api.Test;

import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

import static com.raghavendra.audit.export.SigningKeyPermissionPolicy.Decision;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Platform-independent unit tests for the pure signing-key permission policy. These run on ALL
 * platforms (including Windows) because they operate on an in-memory permission set and never touch
 * the filesystem. The OS-specific act of READING permissions is exercised separately by
 * {@link Ed25519KeyPermissionTest}, which is conditionally skipped on non-POSIX systems.
 */
class SigningKeyPermissionPolicyTest {

    private static Set<PosixFilePermission> ownerOnly() {
        return EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    }

    private static Set<PosixFilePermission> withOwnerPlus(PosixFilePermission extra) {
        Set<PosixFilePermission> p = ownerOnly();
        p.add(extra);
        return p;
    }

    // ---- accessibility classification --------------------------------------------------

    @Test
    void ownerReadWriteOnly_isSafe() {
        assertThat(SigningKeyPermissionPolicy.isGroupOrOtherAccessible(ownerOnly())).isFalse();
        assertThat(SigningKeyPermissionPolicy.evaluate(ownerOnly(), false)).isEqualTo(Decision.SAFE);
        assertThat(SigningKeyPermissionPolicy.evaluate(ownerOnly(), true)).isEqualTo(Decision.SAFE);
    }

    @Test
    void groupReadable_isUnsafe() {
        assertThat(SigningKeyPermissionPolicy.isGroupOrOtherAccessible(
                withOwnerPlus(PosixFilePermission.GROUP_READ))).isTrue();
    }

    @Test
    void groupWritable_isUnsafe() {
        assertThat(SigningKeyPermissionPolicy.isGroupOrOtherAccessible(
                withOwnerPlus(PosixFilePermission.GROUP_WRITE))).isTrue();
    }

    @Test
    void otherReadable_isUnsafe() {
        assertThat(SigningKeyPermissionPolicy.isGroupOrOtherAccessible(
                withOwnerPlus(PosixFilePermission.OTHERS_READ))).isTrue();
    }

    @Test
    void otherWritable_isUnsafe() {
        assertThat(SigningKeyPermissionPolicy.isGroupOrOtherAccessible(
                withOwnerPlus(PosixFilePermission.OTHERS_WRITE))).isTrue();
    }

    // ---- warn/allow vs fail-closed policy ----------------------------------------------

    @Test
    void unsafeKey_underLocalTest_warnsAndAllows() {
        for (PosixFilePermission bad : EnumSet.of(
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
                PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE)) {
            assertThat(SigningKeyPermissionPolicy.evaluate(withOwnerPlus(bad), true))
                    .as("local/test with %s", bad)
                    .isEqualTo(Decision.UNSAFE_WARN);
        }
    }

    @Test
    void unsafeKey_nonLocal_failsClosed() {
        for (PosixFilePermission bad : EnumSet.of(
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
                PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE)) {
            assertThat(SigningKeyPermissionPolicy.evaluate(withOwnerPlus(bad), false))
                    .as("non-local with %s", bad)
                    .isEqualTo(Decision.UNSAFE_FAIL_CLOSED);
        }
    }
}
