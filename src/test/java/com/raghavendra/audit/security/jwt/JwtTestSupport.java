package com.raghavendra.audit.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Test-only JWT signing support using locally generated RSA keys and Nimbus JOSE. This mints REAL
 * signed tokens and exposes a REAL JWK set, so the application's real {@code NimbusJwtDecoder}
 * performs genuine signature/issuer/audience/expiry validation — no {@code spring-security-test}
 * {@code jwt()} shortcut that would bypass the decoder.
 *
 * <p>Two RSA keys are generated: a <em>trusted</em> key published in the JWK set, and a
 * <em>foreign</em> key that is NOT published — signing with it produces a valid-looking token whose
 * signature the decoder cannot verify (wrong-signature case).
 */
public final class JwtTestSupport {

    public static final String ISSUER = "https://issuer.test.local/audit";
    public static final String AUDIENCE = "audit-log-service";

    private final RSAKey trustedKey;   // published in JWKS, kid = "trusted"
    private final RSAKey foreignKey;   // NOT published — for wrong-signature tests

    public JwtTestSupport() {
        try {
            this.trustedKey = new RSAKeyGenerator(2048).keyID("trusted").generate();
            this.foreignKey = new RSAKeyGenerator(2048).keyID("trusted").generate(); // same kid, diff key
        } catch (JOSEException e) {
            throw new IllegalStateException("test key generation failed", e);
        }
    }

    /** The public JWK set JSON to serve at the jwk-set-uri (only the trusted key). */
    public String publicJwkSetJson() {
        return new JWKSet(trustedKey.toPublicJWK()).toString(false);
    }

    // ---- token minting -----------------------------------------------------------------

    /** A standard valid token: correct issuer/audience, exp in the future, nbf in the past. */
    public String validToken(String... scopes) {
        return signRs256(trustedKey, defaults(scopes).build());
    }

    public String tokenWithScopeString(String scopeString) {
        JWTClaimsSet claims = base()
                .claim("scope", scopeString)
                .build();
        return signRs256(trustedKey, claims);
    }

    public String expiredToken(String... scopes) {
        Instant now = Instant.now();
        JWTClaimsSet claims = base()
                .claim("scope", String.join(" ", scopes))
                .issueTime(Date.from(now.minusSeconds(3600)))
                .notBeforeTime(Date.from(now.minusSeconds(3600)))
                .expirationTime(Date.from(now.minusSeconds(1800))) // already expired
                .build();
        return signRs256(trustedKey, claims);
    }

    public String notYetValidToken(String... scopes) {
        Instant now = Instant.now();
        JWTClaimsSet claims = base()
                .claim("scope", String.join(" ", scopes))
                .notBeforeTime(Date.from(now.plusSeconds(3600))) // nbf in the future
                .expirationTime(Date.from(now.plusSeconds(7200)))
                .build();
        return signRs256(trustedKey, claims);
    }

    /** Signed with a key NOT in the JWK set → signature cannot be verified. */
    public String wrongSignatureToken(String... scopes) {
        return signRs256(foreignKey, defaults(scopes).build());
    }

    public String wrongIssuerToken(String... scopes) {
        JWTClaimsSet claims = base()
                .claim("scope", String.join(" ", scopes))
                .issuer("https://evil.example.com")
                .build();
        return signRs256(trustedKey, claims);
    }

    public String wrongAudienceToken(String... scopes) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience("some-other-service")
                .subject("subject-123")
                .issueTime(Date.from(Instant.now().minusSeconds(60)))
                .notBeforeTime(Date.from(Instant.now().minusSeconds(60)))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("scope", String.join(" ", scopes))
                .build();
        return signRs256(trustedKey, claims);
    }

    /** A token carrying a client-supplied roles claim but NO scopes — must grant nothing. */
    public String rolesClaimOnlyToken() {
        JWTClaimsSet claims = base()
                .claim("roles", List.of("ADMIN", "WRITER"))
                .claim("authorities", List.of("ROLE_ADMIN"))
                .build();
        return signRs256(trustedKey, claims);
    }

    /** A structurally-broken token string. */
    public String malformedToken() {
        return "not.a.jwt";
    }

    /**
     * A token signed with HS256 (HMAC) — an algorithm NOT in the RS256/ES256 allow-list. The
     * decoder must reject it on the algorithm allow-list before any key lookup.
     */
    public String disallowedAlgorithmToken(String... scopes) {
        try {
            byte[] secret = new byte[32]; // 256-bit HMAC secret (fixed, deterministic for the test)
            for (int i = 0; i < secret.length; i++) {
                secret[i] = (byte) (i + 1);
            }
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.HS256).build(),
                    defaults(scopes).build());
            jwt.sign(new com.nimbusds.jose.crypto.MACSigner(secret));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("test HS256 token signing failed", e);
        }
    }

    // ---- helpers -----------------------------------------------------------------------

    private JWTClaimsSet.Builder defaults(String... scopes) {
        return base().claim("scope", String.join(" ", scopes));
    }

    private JWTClaimsSet.Builder base() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject("subject-123")
                .issueTime(Date.from(now.minusSeconds(60)))
                .notBeforeTime(Date.from(now.minusSeconds(60)))
                .expirationTime(Date.from(now.plusSeconds(3600)));
    }

    private String signRs256(RSAKey key, JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                    claims);
            jwt.sign(new RSASSASigner(key.toRSAPrivateKey()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("test token signing failed", e);
        }
    }
}
