package com.raghavendra.audit.export;

import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Pure, platform-independent policy for evaluating a private signing-key file's POSIX permissions.
 *
 * <p>This class does <strong>no</strong> filesystem I/O: it takes an already-read permission set
 * and the active-profile flag and returns a {@link Decision}. Keeping the decision logic pure makes
 * it unit-testable on every platform (including Windows, where real POSIX permission views do not
 * exist) — the OS-specific concern of <em>reading</em> the permissions is handled separately by the
 * caller.
 *
 * <p>Policy: a signing key must be owner-only. If it is readable or writable by group or others it
 * is unsafe. An unsafe key <strong>fails closed</strong> (fatal) outside the {@code local}/
 * {@code test} profiles, and is <strong>warned</strong> about (allowed) under them so developer
 * machines are not blocked.
 */
final class SigningKeyPermissionPolicy {

    private SigningKeyPermissionPolicy() {
    }

    /** The outcome of evaluating a key file's permissions. */
    enum Decision {
        /** Owner-only permissions — acceptable. */
        SAFE,
        /** Group/other-accessible under local/test — allowed, but a warning should be logged. */
        UNSAFE_WARN,
        /** Group/other-accessible outside local/test — must fail closed (fatal). */
        UNSAFE_FAIL_CLOSED
    }

    /**
     * True if the permission set grants any access to group or others (read or write). Execute bits
     * are not part of the "exposure" concern for a key file, but any group/other read or write
     * means the key is not owner-private.
     */
    static boolean isGroupOrOtherAccessible(Set<PosixFilePermission> perms) {
        return perms.contains(PosixFilePermission.GROUP_READ)
                || perms.contains(PosixFilePermission.GROUP_WRITE)
                || perms.contains(PosixFilePermission.OTHERS_READ)
                || perms.contains(PosixFilePermission.OTHERS_WRITE);
    }

    /**
     * Evaluate the permission set against the fail-closed/warn policy.
     *
     * @param perms       the file's POSIX permissions (as read by the caller)
     * @param localOrTest whether an explicit {@code local}/{@code test} profile is active
     * @return the decision the caller must act on
     */
    static Decision evaluate(Set<PosixFilePermission> perms, boolean localOrTest) {
        if (!isGroupOrOtherAccessible(perms)) {
            return Decision.SAFE;
        }
        return localOrTest ? Decision.UNSAFE_WARN : Decision.UNSAFE_FAIL_CLOSED;
    }
}
