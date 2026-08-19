package com.raghavendra.audit.event;

import com.raghavendra.audit.event.api.AppendEventRequest;
import com.raghavendra.audit.event.application.AuditEventAppendService;
import com.raghavendra.audit.event.application.DuplicateEventIdException;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Service-layer integration tests for the transactional append: chain linkage, duplicate-id
 * rejection with no chain advance (rollback), and concurrent appends serialized by the
 * FOR UPDATE head lock. Runs against real PostgreSQL 16 (Testcontainers).
 */
@SpringBootTest
@AbstractPostgresIntegrationTest.WithPostgres
class AuditEventAppendServiceTest {

    @Autowired
    private AuditEventAppendService appendService;

    @Autowired
    private AuditEventRepository eventRepository;

    @Autowired
    private AuditChainHeadRepository chainHeadRepository;

    @BeforeEach
    void resetChain() {
        eventRepository.deleteAll();
        chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .ifPresent(h -> {
                    h.resetToEmpty(OffsetDateTime.now());
                    chainHeadRepository.save(h);
                });
    }

    private AppendEventRequest req() {
        return new AppendEventRequest("USER_LOGIN", "actor-1", "USER",
                "CLIENT_ACCOUNT", "acct-1", "SUCCESS", null, null, null, null);
    }

    // ---- append + linkage --------------------------------------------------------------

    @Test
    void append_buildsLinkedChain() {
        var e1 = appendService.append(req(), UUID.randomUUID());
        var e2 = appendService.append(req(), UUID.randomUUID());

        assertThat(e1.getSequenceNumber()).isEqualTo(1L);
        assertThat(e1.getPreviousHash()).isNull();               // genesis
        assertThat(e2.getSequenceNumber()).isEqualTo(2L);
        assertThat(e2.getPreviousHash()).isEqualTo(e1.getContentHash()); // linkage
    }

    // ---- duplicate id → rejected, no chain advance (rollback) --------------------------

    @Test
    void duplicateEventId_isRejected_andChainDoesNotAdvance() {
        UUID id = UUID.randomUUID();
        appendService.append(req(), id);

        long seqBefore = headSequence();
        long countBefore = eventRepository.count();

        assertThatThrownBy(() -> appendService.append(req(), id))
                .isInstanceOf(DuplicateEventIdException.class);

        // No side effects: chain head unchanged and no extra event persisted.
        assertThat(headSequence()).isEqualTo(seqBefore);
        assertThat(eventRepository.count()).isEqualTo(countBefore);
    }

    @Test
    void duplicateEventId_fromConstraint_surfacesAsDataIntegrityViolation_not500() {
        // Force the AUTHORITATIVE path: insert a second event row with the SAME event_id
        // directly (bypassing the service pre-check) to trigger the unique constraint. This is
        // the race that the pre-check cannot close; it must raise DataIntegrityViolationException
        // (which the web handler maps to 409), never an unclassified error.
        UUID id = UUID.randomUUID();
        var first = appendService.append(req(), id);

        var dup = new com.raghavendra.audit.event.domain.AuditEventEntity(
                id, 999L, "a", "USER", "X", "R", "r", "SUCCESS", null,
                first.getEventTimestamp(), first.getRecordedAt(), 1, "{}",
                first.getContentHash(), first.getContentHash());

        assertThatThrownBy(() -> {
            eventRepository.saveAndFlush(dup);
        }).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    // ---- concurrency: FOR UPDATE serializes appends ------------------------------------

    @Test
    void concurrentAppends_produceGapFreeStrictlyIncreasingChain() throws Exception {
        int n = 25;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Callable<Long>> tasks = IntStream.range(0, n)
                    .<Callable<Long>>mapToObj(i -> () ->
                            appendService.append(req(), UUID.randomUUID()).getSequenceNumber())
                    .toList();

            List<Future<Long>> futures = pool.invokeAll(tasks);
            List<Long> sequences = futures.stream().map(f -> {
                try {
                    return f.get();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }).sorted().collect(Collectors.toList());

            // Exactly n events, sequences 1..n with no gaps and no duplicates.
            assertThat(sequences).hasSize(n);
            assertThat(sequences).containsExactlyElementsOf(
                    IntStream.rangeClosed(1, n).mapToObj(Long::valueOf).toList());
            assertThat(eventRepository.count()).isEqualTo(n);
            assertThat(headSequence()).isEqualTo(n);

            // Chain integrity: each event's previousHash == prior event's contentHash.
            var ordered = eventRepository.findAll().stream()
                    .sorted((a, b) -> Long.compare(a.getSequenceNumber(), b.getSequenceNumber()))
                    .toList();
            for (int i = 1; i < ordered.size(); i++) {
                assertThat(ordered.get(i).getPreviousHash())
                        .as("event %d links to event %d", i + 1, i)
                        .isEqualTo(ordered.get(i - 1).getContentHash());
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private long headSequence() {
        return chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .orElseThrow().getCurrentSequence();
    }
}
