package com.raghavendra.audit.export;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

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
        try {
            if (hasText(properties.privateKeyPath())) {
                priv = loadPrivateKey(properties.privateKeyPath());
                if (hasText(properties.publicKeyPath())) {
                    pub = loadPublicKey(properties.publicKeyPath());
                }
            } else if (isLocalOrTestProfile(environment)) {
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

    private PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] der = pemToDer(Files.readString(Path.of(path)), "PRIVATE KEY");
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
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
