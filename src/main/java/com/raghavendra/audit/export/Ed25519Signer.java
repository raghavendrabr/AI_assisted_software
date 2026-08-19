package com.raghavendra.audit.export;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Set;

/**
 * Ed25519 signing for export manifests.
 *
 * <p>The PRIVATE key is loaded from an environment-mounted PEM file
 * ({@code audit.export.private-key-path}); it is NEVER committed. The PUBLIC key (for verifiers)
 * is loaded from {@code audit.export.public-key-path} and may be committed.
 *
 * <p><strong>Fail-closed key policy:</strong> the ephemeral in-memory dev key is permitted ONLY
 * when an explicit {@code local} or {@code test} profile is active. In any other configuration
 * (e.g. a deployed/default profile) a missing {@code audit.export.private-key-path} is a
 * <strong>fatal startup error</strong> — the service fails closed rather than silently signing
 * with a throwaway key. Production MUST provide a real key file (or a managed KMS-backed signer).
 */
@Component
public class Ed25519Signer {

    private static final Logger log = LoggerFactory.getLogger(Ed25519Signer.class);
    private static final String ALGORITHM = "Ed25519";

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String signingKeyId;
    private final boolean ephemeralDevKey;

    public Ed25519Signer(ExportSigningProperties properties, Environment environment) {
        this.signingKeyId = properties.signingKeyId();
        PrivateKey priv = null;
        PublicKey pub = null;
        boolean ephemeral = false;
        boolean localOrTest = isLocalOrTestProfile(environment);
        try {
            if (hasText(properties.privateKeyPath())) {
                priv = loadPrivateKey(properties.privateKeyPath(), localOrTest);
                if (hasText(properties.publicKeyPath())) {
                    pub = loadPublicKey(properties.publicKeyPath());
                }
            } else if (localOrTest) {
                // Ephemeral dev key allowed ONLY under an explicit local/test profile.
                KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGORITHM);
                KeyPair kp = gen.generateKeyPair();
                priv = kp.getPrivate();
                pub = kp.getPublic();
                ephemeral = true;
                log.warn("Export signing is using an EPHEMERAL NON-PRODUCTION Ed25519 dev key "
                        + "(local/test profile). Set audit.export.private-key-path for real use.");
            } else {
                // Fail closed: no key + not a local/test profile.
                throw new IllegalStateException(
                        "No export signing key configured (audit.export.private-key-path is unset) "
                        + "and no local/test profile is active. Refusing to start with an ephemeral "
                        + "signing key. Provide a mounted Ed25519 private key or run with the "
                        + "'local' or 'test' profile.");
            }
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize Ed25519 export signer", e);
        }
        this.privateKey = priv;
        this.publicKey = pub;
        this.ephemeralDevKey = ephemeral;
    }

    private boolean isLocalOrTestProfile(Environment env) {
        for (String p : env.getActiveProfiles()) {
            if ("local".equalsIgnoreCase(p) || "test".equalsIgnoreCase(p)) {
                return true;
            }
        }
        return false;
    }

    public String signingKeyId() {
        return signingKeyId;
    }

    public boolean isEphemeralDevKey() {
        return ephemeralDevKey;
    }

    /** Sign a digest, returning the raw signature bytes. */
    public byte[] sign(byte[] message) {
        try {
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initSign(privateKey);
            sig.update(message);
            return sig.sign();
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    /** The public key as base64 (X.509/SPKI DER), so it can be published in the bundle. */
    public String publicKeyBase64() {
        if (publicKey == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    private PrivateKey loadPrivateKey(String path, boolean localOrTest) throws Exception {
        Path keyPath = Path.of(path);
        checkPrivateKeyPermissions(keyPath, localOrTest);
        byte[] der = pemToDer(Files.readString(keyPath), "PRIVATE KEY");
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    /**
     * Guards the private-key file's on-disk permissions.
     *
     * <p><b>POSIX filesystems:</b> if the file is readable by group or others, that is a
     * misconfiguration — a signing key should be owner-only (e.g. {@code chmod 600}). Outside the
     * {@code local}/{@code test} profiles this <b>fails closed</b> (fatal startup error); under
     * {@code local}/{@code test} it only logs a warning so developer machines are not blocked.
     *
     * <p><b>Non-POSIX filesystems (e.g. Windows):</b> POSIX permission bits do not exist, so this
     * check is not applicable. We detect the unsupported attribute view explicitly and skip the
     * bit-check, relying instead on platform ACLs (NTFS ACLs / file-system access control) to
     * protect the key — this reliance is documented rather than silently assumed.
     *
     * <p>The key's <i>contents</i> are never read or logged here — only its permission metadata.
     */
    private void checkPrivateKeyPermissions(Path keyPath, boolean localOrTest) {
        Set<PosixFilePermission> perms;
        try {
            perms = Files.getPosixFilePermissions(keyPath);
        } catch (UnsupportedOperationException e) {
            // Non-POSIX filesystem (typically Windows). POSIX bits are unavailable; key protection
            // relies on platform ACLs. Documented reliance — not a silent skip.
            log.info("Private signing-key permission check skipped: the filesystem for '{}' does "
                    + "not support POSIX permissions. Ensure the key is protected by platform ACLs.",
                    keyPath.getFileName());
            return;
        } catch (Exception e) {
            // Could not read permission metadata for another reason; do not block startup on it.
            log.warn("Could not verify private signing-key file permissions for '{}': {}",
                    keyPath.getFileName(), e.getClass().getSimpleName());
            return;
        }

        // Delegate the decision to the pure, platform-independent policy (unit-tested separately).
        String message = "Export private signing key is group- or world-accessible; it must be "
                + "owner-only (e.g. chmod 600).";
        switch (SigningKeyPermissionPolicy.evaluate(perms, localOrTest)) {
            case SAFE -> {
                // owner-only — good.
            }
            case UNSAFE_WARN -> log.warn(
                    "{} Allowed under the local/test profile, but fix this before deploying.",
                    message);
            case UNSAFE_FAIL_CLOSED -> throw new IllegalStateException(message);
        }
    }

    private PublicKey loadPublicKey(String path) throws Exception {
        byte[] der = pemToDer(Files.readString(Path.of(path)), "PUBLIC KEY");
        return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
    }

    private byte[] pemToDer(String pem, String type) {
        String base64 = pem.replace("-----BEGIN " + type + "-----", "")
                .replace("-----END " + type + "-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    private boolean hasText(String s) {
        return s != null && !s.isBlank();
    }
}
