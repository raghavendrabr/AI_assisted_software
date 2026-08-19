package com.raghavendra.audit.common.security;

import com.raghavendra.audit.common.config.HardeningProperties;
import com.raghavendra.audit.common.security.jwt.AuditJwtDecoderFactory;
import com.raghavendra.audit.common.security.jwt.JwtProperties;
import com.raghavendra.audit.common.security.jwt.JwtScopeRoleConverter;
import com.raghavendra.audit.common.web.RequestBodySizeLimitFilter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * API-key authentication and per-endpoint authorization (the authorization matrix), plus the
 * request/security hardening wired in Commit A.
 *
 * <p>Authentication is by {@code X-API-Key} (see {@link ApiKeyAuthFilter}); the role is resolved
 * server-side. The client never supplies its own role. Missing/invalid key → 401; wrong role →
 * 403. Roles are distinct capabilities; ADMIN is granted the union explicitly per rule rather
 * than by inheritance.
 *
 * <p>Authorization matrix:
 * <pre>
 *   POST   /api/v1/audit/events            WRITER, ADMIN
 *   GET    /api/v1/audit/events            COMPLIANCE_READER, ADMIN
 *   GET    /api/v1/audit/verify            COMPLIANCE_READER, ADMIN
 *   GET    /api/v1/compliance/access-report COMPLIANCE_READER, ADMIN
 * </pre>
 *
 * <p><strong>Hardening (Commit A):</strong>
 * <ul>
 *   <li>Response security headers: Spring Security's defaults ({@code X-Content-Type-Options:
 *       nosniff}, {@code X-Frame-Options: DENY}, {@code Cache-Control}) are retained, and
 *       {@code Referrer-Policy: no-referrer} + a restrictive {@code Permissions-Policy} are added.
 *       HSTS is emitted only over HTTPS (Spring Security's default {@code requiresSecure} behavior),
 *       so it has no effect on plain-HTTP local runs. No CSP is added (the docs UI is gated
 *       separately and a CSP is only worth adding once verified against a live Swagger UI).</li>
 *   <li>CORS is explicitly disabled — no browser front-end consumes this API today, so no
 *       cross-origin access is granted. Recorded as a deliberate decision, not an omission.</li>
 *   <li>OpenAPI/Swagger exposure is driven by {@code audit.docs.*}: public only when
 *       {@code enabled=true} AND {@code public=true}; if {@code enabled=true} and
 *       {@code public=false}, the docs require ADMIN; otherwise they fall through to
 *       {@code denyAll()}. This is a single filter chain consulting a property — not competing
 *       chains.</li>
 *   <li>A streaming {@link RequestBodySizeLimitFilter} caps request-body size before controllers
 *       read the body.</li>
 * </ul>
 */
@Configuration
@EnableConfigurationProperties({ApiKeyProperties.class, HardeningProperties.class})
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApiKeyService apiKeyService,
                                                   HardeningProperties hardening,
                                                   AuthEventLogger authLog,
                                                   JwtProperties jwtProperties,
                                                   JwtScopeRoleConverter scopeRoleConverter,
                                                   tools.jackson.databind.ObjectMapper objectMapper)
            throws Exception {
        boolean docsEnabled = hardening.getDocs().isEnabled();
        boolean docsPublic = docsEnabled && hardening.getDocs().isPublic();

        http
                .csrf(csrf -> csrf.disable()) // stateless API-key auth; no browser session/CSRF
                // No browser front-end consumes this API; deny cross-origin browser access.
                .cors(cors -> cors.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Retain Spring Security's default headers (nosniff, X-Frame-Options: DENY,
                // Cache-Control) and add Referrer-Policy + Permissions-Policy. HSTS is left at its
                // default, which only applies over HTTPS, so plain-HTTP local runs are unaffected.
                .headers(headers -> headers
                        .referrerPolicy(rp -> rp.policy(
                                ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .permissionsPolicyHeader(pp -> pp.policy(PERMISSIONS_POLICY)))
                .authorizeHttpRequests(auth -> {
                    // OpenAPI/Swagger — gated by audit.docs.*.
                    String[] docPaths = {"/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html"};
                    if (docsPublic) {
                        auth.requestMatchers(docPaths).permitAll();
                    } else if (docsEnabled) {
                        auth.requestMatchers(docPaths).hasRole(ApiRole.ADMIN.name());
                    }
                    // When docs are disabled entirely, no rule is added here, so the doc paths
                    // fall through to denyAll() below (and springdoc is also switched off).

                    auth
                        // Redaction — ADMIN only. (Declared BEFORE the write rule so the more
                        // specific path wins.)
                        .requestMatchers(HttpMethod.POST, "/api/v1/audit/events/*/redact")
                            .hasRole(ApiRole.ADMIN.name())
                        // Retention/archival — ADMIN only.
                        .requestMatchers(HttpMethod.POST, "/api/v1/audit/retention/**")
                            .hasRole(ApiRole.ADMIN.name())
                        // Write API — WRITER or ADMIN.
                        .requestMatchers(HttpMethod.POST, "/api/v1/audit/events")
                            .hasAnyRole(ApiRole.WRITER.name(), ApiRole.ADMIN.name())
                        // Read/query API — COMPLIANCE_READER or ADMIN.
                        .requestMatchers(HttpMethod.GET, "/api/v1/audit/events")
                            .hasAnyRole(ApiRole.COMPLIANCE_READER.name(), ApiRole.ADMIN.name())
                        // Verify — COMPLIANCE_READER or ADMIN.
                        .requestMatchers(HttpMethod.GET, "/api/v1/audit/verify")
                            .hasAnyRole(ApiRole.COMPLIANCE_READER.name(), ApiRole.ADMIN.name())
                        // Compliance report — COMPLIANCE_READER or ADMIN.
                        .requestMatchers(HttpMethod.GET, "/api/v1/compliance/**")
                            .hasAnyRole(ApiRole.COMPLIANCE_READER.name(), ApiRole.ADMIN.name())
                        // Bulk export — COMPLIANCE_READER or ADMIN.
                        .requestMatchers(HttpMethod.GET, "/api/v1/audit/export")
                            .hasAnyRole(ApiRole.COMPLIANCE_READER.name(), ApiRole.ADMIN.name())
                        // DENY everything not explicitly allowed above. This is a fail-closed
                        // default: a newly added endpoint is denied until an explicit rule
                        // grants access, so it can never be accidentally public.
                        .anyRequest().denyAll();
                })
                // Enforce the request-body size cap before authentication/authorization read the
                // body. Placed before the API-key filter (and thus before controller binding).
                .addFilterBefore(new RequestBodySizeLimitFilter(hardening),
                        UsernamePasswordAuthenticationFilter.class)
                // Reject ambiguous both-credentials requests (Bearer + X-API-Key) with 400, before
                // either authentication mechanism runs.
                .addFilterBefore(new DualCredentialGuardFilter(authLog, objectMapper),
                        UsernamePasswordAuthenticationFilter.class)
                // API-key authentication. It never overwrites a JWT authentication and never falls
                // back when a Bearer token is present (see ApiKeyAuthFilter).
                .addFilterBefore(new ApiKeyAuthFilter(apiKeyService, authLog),
                        UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex
                        // No/invalid key (unauthenticated) → 401; authenticated but wrong role → 403.
                        // Use setStatus (not sendError): sendError triggers an internal ERROR
                        // dispatch to /error, which re-enters the security chain as anonymous, hits
                        // denyAll(), and would overwrite a 403 with a 401. setStatus writes the
                        // status directly with no body and no error forward.
                        .authenticationEntryPoint((request, response, authEx) -> {
                            response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED);
                            response.getWriter().flush();
                        })
                        .accessDeniedHandler((request, response, deniedEx) -> {
                            response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN);
                            response.getWriter().flush();
                        }));

        // Conditional JWT resource server: wired ONLY when JWT is enabled AND complete. Otherwise
        // the service runs API-key-only, and any Bearer token is rejected as unauthenticated (401)
        // because no resource server is configured to accept it.
        if (jwtProperties.isComplete()) {
            JwtDecoder decoder = AuditJwtDecoderFactory.build(jwtProperties);
            JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
            converter.setJwtGrantedAuthoritiesConverter(scopeRoleConverter::convert);
            http.oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwt -> jwt
                            .decoder(decoder)
                            .jwtAuthenticationConverter(converter)));
            // Log JWT auth SUCCESS (fingerprint only) after the Bearer filter authenticates. JWT
            // FAILURES are surfaced by the resource server (401 + WWW-Authenticate: Bearer).
            http.addFilterAfter(new JwtAuthEventLoggingFilter(authLog),
                    BearerTokenAuthenticationFilter.class);
        }

        return http.build();
    }

    /**
     * Restrictive Permissions-Policy: deny the common powerful browser features. This API is not
     * consumed by a browser front-end, so no feature is granted.
     */
    private static final String PERMISSIONS_POLICY =
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
            + "accelerometer=(), gyroscope=(), magnetometer=(), fullscreen=()";
}
