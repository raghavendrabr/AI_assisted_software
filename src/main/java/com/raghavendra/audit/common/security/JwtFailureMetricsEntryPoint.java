package com.raghavendra.audit.common.security;

import com.raghavendra.audit.common.observability.AuditMetrics;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * Records a JWT authentication FAILURE metric, then delegates to the standard
 * {@link BearerTokenAuthenticationEntryPoint} so the RFC 6750 {@code WWW-Authenticate: Bearer}
 * challenge (and 401) is emitted unchanged. This is the single site where JWT invalid-token failures
 * are counted — the Bearer filter routes all token-validation failures here, so there is no double
 * counting with the API-key or both-credentials paths.
 */
public class JwtFailureMetricsEntryPoint implements AuthenticationEntryPoint {

    private final AuditMetrics metrics;
    private final BearerTokenAuthenticationEntryPoint delegate = new BearerTokenAuthenticationEntryPoint();

    public JwtFailureMetricsEntryPoint(AuditMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        metrics.authentication(AuditMetrics.Result.FAILURE, AuditMetrics.Method.JWT,
                AuditMetrics.AuthReason.INVALID_TOKEN);
        delegate.commence(request, response, authException);
    }
}
