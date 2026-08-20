package com.raghavendra.audit.common.security.jwt;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wiring for the optional JWT resource-server mode ({@code audit.security.jwt.*}).
 *
 * <p><strong>Conditional activation:</strong>
 * <ul>
 *   <li>disabled (default) or incomplete → no {@link JwtDecoder} bean is created, and the security
 *       chain runs in API-key-only mode;</li>
 *   <li>enabled AND complete → a hardened {@link JwtDecoder} is built by
 *       {@link AuditJwtDecoderFactory};</li>
 *   <li>enabled but <em>incomplete</em> (missing issuer/JWK source or audiences) → a
 *       <strong>fatal startup error</strong>, so a half-configured resource server can never start
 *       and silently accept tokens.</li>
 * </ul>
 *
 * <p>We deliberately bind to {@code audit.security.jwt.*} and build the decoder ourselves rather
 * than setting Spring Boot's {@code spring.security.oauth2.resourceserver.jwt.issuer-uri} — binding
 * an empty placeholder there would trigger Boot's auto-configured resource server (and an issuer
 * round-trip) even when JWT is meant to be off.
 */
@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtSecurityConfig {

    private final JwtProperties properties;

    public JwtSecurityConfig(JwtProperties properties) {
        this.properties = properties;
    }

    /** Fail fast if JWT is switched on but the configuration is incomplete. */
    @PostConstruct
    public void validate() {
        if (properties.isEnabledButIncomplete()) {
            throw new IllegalStateException(
                    "audit.security.jwt.enabled=true but the configuration is incomplete: an "
                    + "issuer-uri or jwk-set-uri AND at least one audience are required. Refusing to "
                    + "start a half-configured JWT resource server.");
        }
    }

    /** The scope→role converter, available for the security chain to use. */
    @Bean
    JwtScopeRoleConverter jwtScopeRoleConverter() {
        return new JwtScopeRoleConverter(properties.getScopeRoles());
    }
}
