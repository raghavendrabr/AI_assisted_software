package com.raghavendra.audit.export;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-platform private-key permission guard. On POSIX filesystems a group/other-readable signing
 * key fails closed outside local/test and only warns under local/test. On non-POSIX filesystems
 * (e.g. Windows) the POSIX bit-check is not applicable and is skipped (reliance on platform ACLs);
 * these POSIX-specific assertions are skipped there via {@link org.junit.jupiter.api.Assumptions}.
 */
class Ed25519KeyPermissionTest {

    private static boolean posixSupported(Path dir) {
        try {
            return Files.getFileStore(dir).supportsFileAttributeView(
                    java.nio.file.attribute.PosixFileAttributeView.class);
        } catch (Exception e) {
            return false;
        }
    }

    /** Write a freshly-generated Ed25519 private key as a PKCS#8 PEM to {@code path}. */
    private static void writePrivateKeyPem(Path path) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = gen.generateKeyPair();
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(kp.getPrivate().getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(path, pem);
    }

    private static ExportSigningProperties props(Path keyPath) {
        return new ExportSigningProperties(keyPath.toString(), null, "kid");
    }

    @Test
    void groupOrWorldReadableKey_failsClosed_outsideLocalTest(@TempDir Path dir) throws Exception {
        assumeTrue(posixSupported(dir), "POSIX permissions not supported on this filesystem");
        Path key = dir.resolve("private.pem");
        writePrivateKeyPem(key);
        // rw-r--r-- : group- and world-readable.
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-r--r--"));

        var env = new MockEnvironment();
        env.setActiveProfiles("production"); // not local/test
        assertThatThrownBy(() -> new Ed25519Signer(props(key), env))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("readable");
    }

    @Test
    void groupOrWorldReadableKey_underLocalTest_warnsButStarts(@TempDir Path dir) throws Exception {
        assumeTrue(posixSupported(dir), "POSIX permissions not supported on this filesystem");
        Path key = dir.resolve("private.pem");
        writePrivateKeyPem(key);
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-r--r--"));

        var env = new MockEnvironment();
        env.setActiveProfiles("test");
        // Should NOT throw: under local/test a bad-perm key is warned about, not fatal.
        assertThatCode(() -> new Ed25519Signer(props(key), env)).doesNotThrowAnyException();
    }

    @Test
    void ownerOnlyKey_isAccepted_evenOutsideLocalTest(@TempDir Path dir) throws Exception {
        assumeTrue(posixSupported(dir), "POSIX permissions not supported on this filesystem");
        Path key = dir.resolve("private.pem");
        writePrivateKeyPem(key);
        Set<PosixFilePermission> ownerOnly =
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        Files.setPosixFilePermissions(key, ownerOnly);

        var env = new MockEnvironment();
        env.setActiveProfiles("production");
        Ed25519Signer signer = new Ed25519Signer(props(key), env);
        assertThat(signer.isEphemeralDevKey()).isFalse();
    }
}
