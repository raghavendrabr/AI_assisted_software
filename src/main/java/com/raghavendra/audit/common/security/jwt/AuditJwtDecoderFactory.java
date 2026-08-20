package com.raghavendra.audit.common.security.jwt;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Builds a hardened {@link NimbusJwtDecoder} from {@link JwtProperties}.
 *
 * <p>The decoder enforces, in order:
 * <ol>
 *   <li><b>Cryptographic signature</b> against the issuer's/JWK-set's keys;</li>
 *   <li>an explicit <b>algorithm allow-list</b> ({@code allowedAlgorithms}) — a token signed with
 *       any other algorithm is rejected at decode time;</li>
 *   <li><b>issuer</b> ({@code iss}) equals {@code issuerUri} (when configured);</li>
 *   <li><b>audience</b> ({@code aud}) intersects the configured {@code audiences};</li>
 *   <li><b>expiration</b> ({@code exp}) and <b>not-before</b> ({@code nbf}) via the timestamp
 *       validator.</li>
 * </ol>
 *
 * <p>When a {@code jwkSetUri} is configured it is used directly (no issuer discovery round-trip);
 * otherwise the issuer location is used. Structurally invalid tokens fail inside Nimbus decoding.
 */
public final class AuditJwtDecoderFactory {

    private AuditJwtDecoderFactory() {
    }

    public static NimbusJwtDecoder build(JwtProperties props) {
        Set<SignatureAlgorithm> algs = resolveAlgorithms(props.getAllowedAlgorithms());

        NimbusJwtDecoder decoder;
        if (hasText(props.getJwkSetUri())) {
            decoder = NimbusJwtDecoder.withJwkSetUri(props.getJwkSetUri())
                    .jwsAlgorithms(set -> set.addAll(algs))
                    .build();
        } else {
            // Issuer-location build discovers the JWKS from the issuer's OIDC metadata.
            decoder = NimbusJwtDecoder.withIssuerLocation(props.getIssuerUri())
                    .jwsAlgorithms(set -> set.addAll(algs))
                    .build();
        }

        decoder.setJwtValidator(buildValidator(props));
        return decoder;
    }

    private static Set<SignatureAlgorithm> resolveAlgorithms(List<String> names) {
        Set<SignatureAlgorithm> algs = new java.util.LinkedHashSet<>();
        for (String name : names) {
            SignatureAlgorithm alg = SignatureAlgorithm.from(name.trim());
            if (alg == null) {
                throw new IllegalStateException(
                        "audit.security.jwt.allowed-algorithms: unsupported algorithm '" + name + "'");
            }
            algs.add(alg);
        }
        if (algs.isEmpty()) {
            throw new IllegalStateException(
                    "audit.security.jwt.allowed-algorithms must list at least one algorithm");
        }
        return algs;
    }

    private static OAuth2TokenValidator<Jwt> buildValidator(JwtProperties props) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        // exp + nbf (with a small default clock skew).
        validators.add(new JwtTimestampValidator());
        // issuer, when configured.
        if (hasText(props.getIssuerUri())) {
            validators.add(new JwtIssuerValidator(props.getIssuerUri()));
        }
        // audience: the token's aud must intersect the configured audiences.
        List<String> accepted = props.getAudiences();
        validators.add(new JwtClaimValidator<List<String>>(JwtClaimNames.AUD, aud ->
                aud != null && aud.stream().anyMatch(accepted::contains)));
        return new DelegatingOAuth2TokenValidator<>(validators);
    }

    private static boolean hasText(String s) {
        return s != null && !s.isBlank();
    }
}
