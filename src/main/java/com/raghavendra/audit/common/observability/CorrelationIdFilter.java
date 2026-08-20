package com.raghavendra.audit.common.observability;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Assigns a correlation / request id to every request and exposes it as {@code X-Request-Id} on the
 * response and as the {@code requestId} MDC key (so it appears in structured logs).
 *
 * <p>Behavior:
 * <ul>
 *   <li>An inbound {@code X-Request-Id} is accepted ONLY if it matches a bounded safe pattern
 *       (1–64 chars of {@code [A-Za-z0-9._-]}); otherwise a fresh UUID is generated. An invalid or
 *       oversized value is never logged or echoed — it is simply replaced.</li>
 *   <li>The W3C {@code traceparent} header is <strong>never</strong> treated as the requestId
 *       (distributed tracing is deferred; see ADR 0012).</li>
 *   <li>The id is placed in MDC and <strong>removed in a {@code finally}</strong> block so it never
 *       leaks to an unrelated request handled later on the same thread.</li>
 * </ul>
 *
 * <p>Registered as the FIRST filter in the chain (before the body-size, dual-credential, API-key,
 * and JWT filters) so that 400 / 401 / 403 / 413 responses also carry a request id. It runs on the
 * default request dispatch only; it is intentionally NOT applied to ASYNC / ERROR re-dispatches, so
 * it does not duplicate the MDC value or clear it prematurely while the original thread is still
 * writing the response.
 */
public class CorrelationIdFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID_HEADER = "X-Request-Id";
    public static final String MDC_KEY = "requestId";

    private static final Pattern SAFE_ID = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String requestId = resolve(request.getHeader(REQUEST_ID_HEADER));
        MDC.put(MDC_KEY, requestId);
        response.setHeader(REQUEST_ID_HEADER, requestId);
        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }

    /**
     * Re-apply the current request's correlation id to the response header. Filters that call
     * {@code response.reset()} (which clears buffered headers) before writing an early error
     * response should call this so the {@code X-Request-Id} header survives on 400/413 responses.
     * No-op if there is no request id in MDC.
     */
    public static void reapplyRequestId(HttpServletResponse response) {
        String requestId = MDC.get(MDC_KEY);
        if (requestId != null && !response.isCommitted()) {
            response.setHeader(REQUEST_ID_HEADER, requestId);
        }
    }

    /** Accept a safe inbound id; otherwise (null / invalid / oversized) generate a UUID. */
    private static String resolve(String inbound) {
        if (inbound != null && SAFE_ID.matcher(inbound).matches()) {
            return inbound;
        }
        return UUID.randomUUID().toString();
    }

    /**
     * Only filter the initial REQUEST dispatch — not ASYNC or ERROR re-dispatches — so MDC is set
     * once and cleared once per logical request, with no cross-dispatch duplication or leakage.
     */
    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return true;
    }

    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return true;
    }
}
