package com.raghavendra.audit.observability;

import com.raghavendra.audit.common.observability.CorrelationIdFilter;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CorrelationIdFilter}: id resolution, MDC clearing in finally, and no
 * cross-thread leakage under concurrency.
 */
class CorrelationIdFilterTest {

    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private final CorrelationIdFilter filter = new CorrelationIdFilter();

    private MockHttpServletResponse invoke(String inboundId) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/audit/verify");
        if (inboundId != null) {
            req.addHeader(CorrelationIdFilter.REQUEST_ID_HEADER, inboundId);
        }
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, (rq, rs) -> {
            // Inside the chain, MDC must be populated.
            assertThat(MDC.get(CorrelationIdFilter.MDC_KEY)).isNotBlank();
        });
        return res;
    }

    @Test
    void validId_isEchoed_andMdcClearedAfter() throws Exception {
        MockHttpServletResponse res = invoke("good-id_1.2");
        assertThat(res.getHeader(CorrelationIdFilter.REQUEST_ID_HEADER)).isEqualTo("good-id_1.2");
        assertThat(MDC.get(CorrelationIdFilter.MDC_KEY)).isNull(); // cleared in finally
    }

    @Test
    void invalidId_replacedWithUuid() throws Exception {
        MockHttpServletResponse res = invoke("has space and\ttab");
        String id = res.getHeader(CorrelationIdFilter.REQUEST_ID_HEADER);
        assertThat(SAFE.matcher(id).matches()).isTrue();
        assertThat(id).doesNotContain(" ").doesNotContain("\t");
    }

    @Test
    void missingId_generatesUuid() throws Exception {
        String id = invoke(null).getHeader(CorrelationIdFilter.REQUEST_ID_HEADER);
        assertThat(SAFE.matcher(id).matches()).isTrue();
    }

    @Test
    void concurrentRequests_doNotLeakIdsBetweenThreads() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<String> seen = ConcurrentHashMap.newKeySet();
        Set<String> mismatches = ConcurrentHashMap.newKeySet();

        for (int i = 0; i < threads; i++) {
            final String myId = "id-" + i;
            pool.submit(() -> {
                try {
                    start.await();
                    MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/audit/verify");
                    req.addHeader(CorrelationIdFilter.REQUEST_ID_HEADER, myId);
                    MockHttpServletResponse res = new MockHttpServletResponse();
                    filter.doFilter(req, res, (rq, rs) -> {
                        // The MDC value seen inside this thread must be exactly this thread's id.
                        if (!myId.equals(MDC.get(CorrelationIdFilter.MDC_KEY))) {
                            mismatches.add(myId);
                        }
                    });
                    seen.add(res.getHeader(CorrelationIdFilter.REQUEST_ID_HEADER));
                } catch (Exception e) {
                    mismatches.add("ex-" + myId);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        assertThat(mismatches).isEmpty();          // no thread saw another thread's id in MDC
        assertThat(seen).hasSize(threads);         // each request kept its own id
    }
}
