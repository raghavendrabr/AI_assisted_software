package com.raghavendra.audit.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Authenticates requests by the {@code X-API-Key} header.
 *
 * <p>The client sends only the key; the role is resolved server-side by {@link ApiKeyService}.
 * On a valid key, an authenticated token is placed in the security context with authority
 * {@code ROLE_<role>}. On a missing/invalid key, no authentication is set and the request
 * proceeds to Spring Security's authorization rules, which reject it with 401/403. The client
 * cannot supply its own role — only the key.
 */
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-API-Key";

    private final ApiKeyService apiKeyService;

    public ApiKeyAuthFilter(ApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String presentedKey = request.getHeader(API_KEY_HEADER);
        Optional<ApiRole> role = apiKeyService.resolveRole(presentedKey);

        role.ifPresent(r -> {
            var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + r.name()));
            // Principal is the ROLE only — never the submitted key or its digest — so the key
            // cannot leak via the security context, request attributes, or downstream logging.
            var auth = new UsernamePasswordAuthenticationToken(
                    "api-key:" + r.name(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
        });

        // This filter logs nothing. On failure, Spring Security's entry point / access-denied
        // handler (SecurityConfig) writes only an HTTP status — no key, no digest, no body.
        filterChain.doFilter(request, response);
    }
}
