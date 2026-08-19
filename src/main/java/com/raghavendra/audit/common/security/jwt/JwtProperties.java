package com.raghavendra.audit.common.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuration for optional OAuth2/OIDC JWT authentication ({@code audit.security.jwt.*}),
 * running alongside the existing API-key authentication (dual-mode).
 *
 * <p>JWT is <strong>off by default</strong>. It becomes active only when {@code enabled=true} AND
 * the configuration is complete (an {@code issuer-uri} or {@code jwk-set-uri}, and at least one
 * audience). This is bound to a dedicated namespace on purpose: we do NOT set Spring Boot's
 * standard {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}, because binding an empty
 * placeholder there would trigger Boot's auto-configured resource server (and a startup attempt to
 * reach the issuer). Instead the {@link JwtSecurityConfig} builds the {@code JwtDecoder} itself,
 * only when the config is complete.
 *
 * <p>The scope→role mapping is configurable but defaults to the three trusted scopes. Only mapped
 * scopes yield authority; any {@code roles}/{@code authorities} claim supplied by the client is
 * ignored, and there is no default role.
 */
@ConfigurationProperties(prefix = "audit.security.jwt")
public class JwtProperties {

    /** Master switch. When false (default) the service runs in API-key-only mode. */
    private boolean enabled = false;

    /**
     * OIDC issuer URI. When set, the JWKS is discovered from the issuer and the {@code iss} claim
     * must equal it. Either this or {@link #jwkSetUri} must be present when enabled.
     */
    private String issuerUri;

    /**
     * Explicit JWK Set URI. Optional alternative to discovery via {@link #issuerUri} (e.g. when the
     * JWKS endpoint is not derivable from the issuer). When both are set, the issuer is still
     * validated against {@link #issuerUri}.
     */
    private String jwkSetUri;

    /** Accepted audiences ({@code aud}). At least one is required when enabled. */
    private List<String> audiences = List.of();

    /**
     * Allowed JWS signing algorithms (allow-list), e.g. {@code RS256}, {@code ES256}. A token
     * signed with any other algorithm is rejected. Defaults to RS256 + ES256.
     */
    private List<String> allowedAlgorithms = List.of("RS256", "ES256");

    /**
     * Trusted scope → role mapping. Keys are OAuth2 scope strings; values are {@link
     * com.raghavendra.audit.common.security.ApiRole} names. Defaults to the three trusted scopes.
     * Only entries listed here grant authority.
     */
    private Map<String, String> scopeRoles = defaultScopeRoles();

    private static Map<String, String> defaultScopeRoles() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("audit.write", "WRITER");
        m.put("audit.read", "COMPLIANCE_READER");
        m.put("audit.admin", "ADMIN");
        return m;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getIssuerUri() {
        return issuerUri;
    }

    public void setIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
    }

    public String getJwkSetUri() {
        return jwkSetUri;
    }

    public void setJwkSetUri(String jwkSetUri) {
        this.jwkSetUri = jwkSetUri;
    }

    public List<String> getAudiences() {
        return audiences;
    }

    public void setAudiences(List<String> audiences) {
        this.audiences = audiences == null ? List.of() : audiences;
    }

    public List<String> getAllowedAlgorithms() {
        return allowedAlgorithms;
    }

    public void setAllowedAlgorithms(List<String> allowedAlgorithms) {
        this.allowedAlgorithms =
                (allowedAlgorithms == null || allowedAlgorithms.isEmpty())
                        ? List.of("RS256", "ES256")
                        : allowedAlgorithms;
    }

    public Map<String, String> getScopeRoles() {
        return scopeRoles;
    }

    public void setScopeRoles(Map<String, String> scopeRoles) {
        this.scopeRoles = (scopeRoles == null || scopeRoles.isEmpty())
                ? defaultScopeRoles()
                : scopeRoles;
    }

    /**
     * True when JWT is switched on AND the configuration is complete enough to build a decoder:
     * a source of keys (issuer or JWK set URI) and at least one audience.
     */
    public boolean isComplete() {
        boolean hasKeySource = hasText(issuerUri) || hasText(jwkSetUri);
        return enabled && hasKeySource && !audiences.isEmpty();
    }

    /** True when enabled but missing required pieces — this must fail startup, not silently pass. */
    public boolean isEnabledButIncomplete() {
        return enabled && !isComplete();
    }

    private static boolean hasText(String s) {
        return s != null && !s.isBlank();
    }
}
