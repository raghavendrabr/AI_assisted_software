package com.raghavendra.audit.export;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for export signing.
 *
 * @param privateKeyPath path to the Ed25519 PRIVATE key (PKCS#8 PEM). From the environment /
 *        a mounted secret; NEVER committed. If blank, the service starts but export is disabled
 *        (signing unavailable) rather than using an insecure default.
 * @param publicKeyPath  path to the Ed25519 PUBLIC key (X.509 PEM). May be committed (public).
 * @param signingKeyId   an identifier for the signing key, echoed in the manifest so a verifier
 *        knows which public key to use.
 */
@ConfigurationProperties(prefix = "audit.export")
public record ExportSigningProperties(
        String privateKeyPath,
        String publicKeyPath,
        String signingKeyId
) {
    public ExportSigningProperties {
        if (signingKeyId == null || signingKeyId.isBlank()) {
            signingKeyId = "audit-export-key-dev";
        }
    }
}
