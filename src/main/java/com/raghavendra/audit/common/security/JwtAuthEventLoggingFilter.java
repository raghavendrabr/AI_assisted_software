package com.raghavendra.audit.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Emits a single sanitized JWT authentication-success log line, using a stable fingerprint of the
 * subject (never the raw subject text). Wired only when JWT mode is active, and placed after the
 * resource server's Bearer filter so authentication has already run. JWT <em>failures</em> are
 * surfaced by the resource server (401 + {@code WWW-Authenticate: Bearer}); this filter records only
 * the success side, symmetric with the API-key success log.
 */
public class JwtAuthEventLoggingFilter extends OncePerRequestFilter {

    private final AuthEventLogger authLog;

    public JwtAuthEventLoggingFilter(AuthEventLogger authLog) {
        this.authLog = authLog;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken jwtAuth && jwtAuth.isAuthenticated()) {
            // Fingerprint of the subject only — never the raw subject or any claim text.
            String principal = AuthEventLogger.jwtSubjectFingerprint(jwtAuth.getToken().getSubject());
            authLog.log(AuthEventLogger.Method.JWT, AuthEventLogger.Result.SUCCESS,
                    "valid-token", principal);
        }
        filterChain.doFilter(request, response);
    }
}
