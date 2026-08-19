package com.raghavendra.audit.common.security;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * API-key authentication and per-endpoint authorization (the authorization matrix).
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
 *   (OpenAPI/Swagger docs are public for the prototype)
 * </pre>
 */
@Configuration
@EnableConfigurationProperties(ApiKeyProperties.class)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApiKeyService apiKeyService)
            throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // stateless API-key auth; no browser session/CSRF
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Public: API docs (prototype convenience).
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html")
                            .permitAll()
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
                        // DENY everything not explicitly allowed above. This is a fail-closed
                        // default: a newly added endpoint is denied until an explicit rule
                        // grants access, so it can never be accidentally public.
                        .anyRequest().denyAll())
                .addFilterBefore(new ApiKeyAuthFilter(apiKeyService),
                        UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex
                        // No/invalid key (unauthenticated) → 401; authenticated but wrong role → 403.
                        .authenticationEntryPoint((request, response, authEx) ->
                                response.sendError(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED))
                        .accessDeniedHandler((request, response, deniedEx) ->
                                response.sendError(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN)));

        return http.build();
    }
}
