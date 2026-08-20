package com.raghavendra.audit.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Authenticates requests by the {@code X-API-Key} header — one half of the dual-mode
 * (JWT + API-key) scheme.
 *
 * <p>The client sends only the key; the role is resolved server-side by {@link ApiKeyService}. On a
 * valid key, an authenticated token is placed in the security context with authority
 * {@code ROLE_<role>}. The client cannot supply its own role — only the key.
 *
 * <p><strong>Dual-mode safety rules enforced here:</strong>
 * <ul>
 *   <li><b>Never overwrite an existing JWT authentication.</b> If the JWT filter (which runs
 *       earlier) already authenticated the request, this filter does nothing.</li>
 *   <li><b>No fallback from a Bearer token.</b> If an {@code Authorization: Bearer} header is
 *       present, this filter does NOT attempt API-key auth — so an <em>invalid</em> Bearer token
 *       results in 401 rather than silently falling back to an API key. (The both-credentials case
 *       — Bearer AND X-API-Key — is rejected as 400 earlier, by {@link DualCredentialGuardFilter}.)</li>
 * </ul>
 * On a missing/invalid key with no Bearer, no authentication is set and the request proceeds to the
 * authorization rules, which reject it with 401/403.
 */
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-API-Key";
    private static final String BEARER_PREFIX = "Bearer ";

    private final ApiKeyService apiKeyService;
    private final AuthEventLogger authLog;
    private final com.raghavendra.audit.common.observability.AuditMetrics metrics;

    public ApiKeyAuthFilter(ApiKeyService apiKeyService, AuthEventLogger authLog,
                            com.raghavendra.audit.common.observability.AuditMetrics metrics) {
        this.apiKeyService = apiKeyService;
        this.authLog = authLog;
        this.metrics = metrics;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // Rule 1: never replace an existing (JWT) authentication.
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing != null && existing.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Rule 2: if a Bearer token is present, do NOT fall back to API-key auth. Let the JWT path
        // (and its entry point) decide the outcome — an invalid Bearer must not become an API-key
        // success.
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String presentedKey = request.getHeader(API_KEY_HEADER);
        Optional<ApiKeyService.ResolvedKey> resolved = apiKeyService.resolve(presentedKey);

        if (resolved.isPresent()) {
            ApiKeyService.ResolvedKey rk = resolved.get();
            var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + rk.role().name()));
            // Principal is the ROLE only — never the submitted key or its digest — so the key
            // cannot leak via the security context, request attributes, or downstream logging.
            var auth = new UsernamePasswordAuthenticationToken(
                    "api-key:" + rk.role().name(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
            // Sanitized success log + metric (single site for API-key success).
            authLog.log(AuthEventLogger.Method.API_KEY, AuthEventLogger.Result.SUCCESS,
                    "valid-key", rk.keyId());
            metrics.authentication(
                    com.raghavendra.audit.common.observability.AuditMetrics.Result.SUCCESS,
                    com.raghavendra.audit.common.observability.AuditMetrics.Method.API_KEY,
                    com.raghavendra.audit.common.observability.AuditMetrics.AuthReason.VALID_KEY);
        } else if (presentedKey != null && !presentedKey.isBlank()) {
            // A key was presented but did not resolve. Log the failure without the key (single site
            // for API-key failure).
            authLog.log(AuthEventLogger.Method.API_KEY, AuthEventLogger.Result.FAILURE,
                    "unknown-key", null);
            metrics.authentication(
                    com.raghavendra.audit.common.observability.AuditMetrics.Result.FAILURE,
                    com.raghavendra.audit.common.observability.AuditMetrics.Method.API_KEY,
                    com.raghavendra.audit.common.observability.AuditMetrics.AuthReason.UNKNOWN_KEY);
        }

        filterChain.doFilter(request, response);
    }
}
