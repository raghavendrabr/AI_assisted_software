package com.raghavendra.audit.common.security;

import com.raghavendra.audit.event.api.ApiError;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.List;

/**
 * Rejects requests that present <strong>both</strong> an {@code Authorization: Bearer} token and an
 * {@code X-API-Key} header. Supplying two credentials is ambiguous — rather than silently choosing
 * one (which could mask a mistake or a downgrade attempt), the request is rejected with a safe
 * <strong>400</strong>.
 *
 * <p>Runs before the JWT and API-key authentication filters so the ambiguity is caught before
 * either mechanism authenticates. The response is a structured {@link ApiError} (JSON) with a
 * static message; it never echoes either credential, and it carries no {@code WWW-Authenticate}
 * header (this is a request-shape error, not an authentication challenge).
 */
public class DualCredentialGuardFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthEventLogger authLog;
    private final ObjectMapper objectMapper;

    public DualCredentialGuardFilter(AuthEventLogger authLog, ObjectMapper objectMapper) {
        this.authLog = authLog;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        boolean hasBearer = authHeader != null && authHeader.startsWith(BEARER_PREFIX);
        boolean hasApiKey = hasText(request.getHeader(ApiKeyAuthFilter.API_KEY_HEADER));

        if (hasBearer && hasApiKey) {
            authLog.log(AuthEventLogger.Method.BOTH_REJECTED, AuthEventLogger.Result.FAILURE,
                    "both-credentials", null);
            if (!response.isCommitted()) {
                response.reset();
                response.setStatus(HttpStatus.BAD_REQUEST.value()); // 400
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                // Structured ApiError; static message, no credential echoed.
                ApiError error = ApiError.of(HttpStatus.BAD_REQUEST.value(), "Bad Request",
                        "Provide either a Bearer token or an API key, not both", List.of());
                objectMapper.writeValue(response.getWriter(), error);
            }
            return;
        }
        filterChain.doFilter(request, response);
    }

    private static boolean hasText(String s) {
        return s != null && !s.isBlank();
    }
}
