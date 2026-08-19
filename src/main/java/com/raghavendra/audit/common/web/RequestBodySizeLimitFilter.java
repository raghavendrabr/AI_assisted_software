package com.raghavendra.audit.common.web;

import com.raghavendra.audit.common.config.HardeningProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Caps the size of request bodies on the write API, defending against memory/CPU exhaustion from
 * oversized uploads. It enforces the limit two ways, and neither reads or caches the whole body:
 *
 * <ol>
 *   <li><b>Early {@code Content-Length} check.</b> When the client declares a length over the
 *       limit, the request is rejected immediately with 413 — before any body bytes are read.</li>
 *   <li><b>Streaming byte count.</b> For chunked / unknown-length bodies (no reliable
 *       {@code Content-Length}), the request's {@link ServletInputStream} is wrapped to count
 *       bytes <em>as the controller reads them</em> and abort at the limit. This catches a body
 *       that lies about (or omits) its length.</li>
 * </ol>
 *
 * <p>The streaming overrun is signalled by {@link PayloadTooLargeException}, mapped to a safe 413
 * by the API exception handler. The early check writes a minimal 413 body directly. Neither path
 * ever echoes any received bytes.
 *
 * <p>Scope: only requests that carry a body to the application API ({@code POST}/{@code PUT}/
 * {@code PATCH} under {@code /api/v1/}). Reads (GET) and non-API paths (docs, actuator later) are
 * untouched.
 */
public class RequestBodySizeLimitFilter extends OncePerRequestFilter {

    private final long maxBytes;

    public RequestBodySizeLimitFilter(HardeningProperties properties) {
        this.maxBytes = properties.getLimits().getMaxRequestBytes();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String method = request.getMethod();
        boolean bodyMethod = HttpMethod.POST.matches(method)
                || HttpMethod.PUT.matches(method)
                || HttpMethod.PATCH.matches(method);
        String uri = request.getRequestURI();
        boolean apiPath = uri != null && uri.startsWith("/api/v1/");
        return !(bodyMethod && apiPath);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // (1) Early rejection when a Content-Length is present and already over the limit.
        long declared = request.getContentLengthLong();
        if (declared >= 0 && declared > maxBytes) {
            writePayloadTooLarge(response);
            return;
        }
        // (2) Otherwise wrap so bytes are counted as they are actually read (handles chunked /
        //     unknown-length and a Content-Length that under-reports the real body).
        filterChain.doFilter(new LimitingRequestWrapper(request, maxBytes), response);
    }

    private static void writePayloadTooLarge(HttpServletResponse response) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.reset();
        response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE); // 413
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.CONNECTION, "close");
        // Minimal, static body — no received bytes are echoed.
        response.getWriter().write(
                "{\"status\":413,\"error\":\"Payload Too Large\","
                + "\"message\":\"Request body exceeds the maximum permitted size\"}");
    }

    /** Wraps the request to expose a byte-counting, limit-enforcing input stream. */
    private static final class LimitingRequestWrapper extends HttpServletRequestWrapper {
        private final long maxBytes;

        LimitingRequestWrapper(HttpServletRequest request, long maxBytes) {
            super(request);
            this.maxBytes = maxBytes;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            return new LimitingServletInputStream(super.getInputStream(), maxBytes);
        }
    }

    /**
     * A {@link ServletInputStream} that counts bytes as they are read and throws
     * {@link PayloadTooLargeException} once the cumulative count exceeds the limit. It never
     * buffers the body — it only tracks a running total, so memory use is constant regardless of
     * body size.
     */
    private static final class LimitingServletInputStream extends ServletInputStream {
        private final ServletInputStream delegate;
        private final long maxBytes;
        private long count;

        LimitingServletInputStream(ServletInputStream delegate, long maxBytes) {
            this.delegate = delegate;
            this.maxBytes = maxBytes;
        }

        private void add(int read) {
            if (read <= 0) {
                return;
            }
            count += read;
            if (count > maxBytes) {
                throw new PayloadTooLargeException("Request body exceeds the maximum permitted size");
            }
        }

        @Override
        public int read() throws IOException {
            int b = delegate.read();
            if (b != -1) {
                add(1);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = delegate.read(b, off, len);
            add(n);
            return n;
        }

        @Override
        public int read(byte[] b) throws IOException {
            int n = delegate.read(b);
            add(n);
            return n;
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            delegate.setReadListener(readListener);
        }

        @Override
        public int available() throws IOException {
            return delegate.available();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
