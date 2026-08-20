package com.raghavendra.audit.export;

import com.raghavendra.audit.amendment.domain.AuditAmendmentEntity;
import com.raghavendra.audit.amendment.domain.AuditAmendmentRepository;
import com.raghavendra.audit.common.hash.HexFormatUtil;
import com.raghavendra.audit.event.application.EventRow;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.retention.domain.AuditEventArchiveRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Builds a self-contained, Ed25519-signed export bundle for all records matching a filter
 * ({@code resourceId} or {@code actorId}), spanning active AND archived events.
 *
 * <p>The signed manifest binds: exportId, exportedAt, the filter, recordCount, the ordered event
 * content hashes, the amendment hashes touching those events, and a chain-head snapshot. A
 * recipient can independently recompute event/amendment hashes and verify the signature. Runs in a
 * REPEATABLE_READ snapshot so the exported set and the chain-head snapshot are coherent.
 */
@Service
public class ExportService {

    private static final DateTimeFormatter UTC =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'");

    private final AuditEventRepository eventRepository;
    private final AuditEventArchiveRepository archiveRepository;
    private final AuditAmendmentRepository amendmentRepository;
    private final AuditChainHeadRepository chainHeadRepository;
    private final Ed25519Signer signer;
    private final Clock clock;
    private final com.raghavendra.audit.common.observability.AuditMetrics metrics;

    public ExportService(AuditEventRepository eventRepository,
                         AuditEventArchiveRepository archiveRepository,
                         AuditAmendmentRepository amendmentRepository,
                         AuditChainHeadRepository chainHeadRepository,
                         Ed25519Signer signer,
                         Clock clock,
                         com.raghavendra.audit.common.observability.AuditMetrics metrics) {
        this.eventRepository = eventRepository;
        this.archiveRepository = archiveRepository;
        this.amendmentRepository = amendmentRepository;
        this.chainHeadRepository = chainHeadRepository;
        this.signer = signer;
        this.clock = clock;
        this.metrics = metrics;
    }

    public enum FilterType { RESOURCE_ID, ACTOR_ID }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public ExportBundle export(FilterType filterType, String filterValue) {
        try {
            ExportBundle bundle = doExport(filterType, filterValue);
            // Success = a bundle was built AND signed (not a DB commit, so counted directly).
            metrics.exportSuccess();
            return bundle;
        } catch (RuntimeException e) {
            metrics.exportFailure();
            throw e;
        }
    }

    private ExportBundle doExport(FilterType filterType, String filterValue) {
        // Gather matching events from active + archive, ordered by sequence.
        List<EventRow> rows = new ArrayList<>();
        eventRepository.findAllByOrderBySequenceNumberAsc().stream()
                .map(EventRow::of).filter(r -> matches(r, filterType, filterValue)).forEach(rows::add);
        archiveRepository.findAllByOrderBySequenceNumberAsc().stream()
                .map(EventRow::of).filter(r -> matches(r, filterType, filterValue)).forEach(rows::add);
        rows.sort(Comparator.comparingLong(EventRow::sequenceNumber));

        Set<Long> exportedSequences = new HashSet<>();
        rows.forEach(r -> exportedSequences.add(r.sequenceNumber()));

        // Amendments that touch an exported event (REDACTION by target; ARCHIVE amendments are
        // range-bound and included when they cover an exported sequence).
        List<AuditAmendmentEntity> relevantAmendments = amendmentRepository
                .findAllByOrderByAmendmentSeqAsc().stream()
                .filter(a -> touchesExported(a, exportedSequences))
                .toList();

        String exportedAt = OffsetDateTime.now(clock)
                .withOffsetSameInstant(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS).format(UTC);

        List<ExportBundle.ExportedEvent> events = rows.stream().map(this::toExportedEvent).toList();
        List<ExportBundle.ExportedAmendment> amendments =
                relevantAmendments.stream().map(this::toExportedAmendment).toList();

        List<String> eventHashes = events.stream().map(ExportBundle.ExportedEvent::contentHash).toList();
        List<String> amendmentHashes = amendments.stream().map(ExportBundle.ExportedAmendment::contentHash).toList();

        AuditChainHeadEntity head = chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID).orElseThrow();
        ExportBundle.ChainHeadSnapshot snapshot = new ExportBundle.ChainHeadSnapshot(
                head.getCurrentSequence(), hex(head.getCurrentHash()),
                head.getLastAmendmentSeq(), hex(head.getAmendmentHeadHash()));

        ExportBundle.Manifest manifest = new ExportBundle.Manifest(
                UUID.randomUUID().toString(), exportedAt,
                filterType == FilterType.RESOURCE_ID ? "resourceId" : "actorId", filterValue,
                events.size(), eventHashes, amendmentHashes, snapshot, signer.signingKeyId());

        byte[] digest = ExportManifestCanonicalizer.digest(manifest);
        String signature = java.util.Base64.getEncoder().encodeToString(signer.sign(digest));

        return new ExportBundle(manifest, events, amendments, signature, signer.publicKeyBase64());
    }

    private boolean matches(EventRow r, FilterType type, String value) {
        return type == FilterType.RESOURCE_ID ? value.equals(r.resourceId()) : value.equals(r.actorId());
    }

    private boolean touchesExported(AuditAmendmentEntity a, Set<Long> exportedSequences) {
        if (a.getTargetSequenceNumber() != null) {
            return exportedSequences.contains(a.getTargetSequenceNumber());
        }
        return false; // ARCHIVE amendments (null target) are not tied to a single exported event
    }

    private ExportBundle.ExportedEvent toExportedEvent(EventRow r) {
        return new ExportBundle.ExportedEvent(
                r.sequenceNumber(), r.eventId().toString(), r.schemaVersion(), r.actorId(),
                r.actorType(), r.eventType(), r.resourceType(), r.resourceId(), r.outcome(),
                r.businessReason(), r.eventTimestamp().withOffsetSameInstant(ZoneOffset.UTC).format(UTC),
                r.recordedAt().withOffsetSameInstant(ZoneOffset.UTC).format(UTC),
                r.payload(), hex(r.previousHash()), hex(r.contentHash()), r.archived());
    }

    private ExportBundle.ExportedAmendment toExportedAmendment(AuditAmendmentEntity a) {
        return new ExportBundle.ExportedAmendment(
                a.getAmendmentSeq(), a.getAmendmentId().toString(), a.getSchemaVersion(),
                a.getOperation(), a.getTargetSequenceNumber(), a.getDetail(), a.getActorId(),
                a.getRecordedAt().withOffsetSameInstant(ZoneOffset.UTC).format(UTC),
                hex(a.getPreviousAmendmentHash()), hex(a.getContentHash()));
    }

    private String hex(byte[] b) {
        return b == null ? null : HexFormatUtil.toLowerHex(b);
    }
}
