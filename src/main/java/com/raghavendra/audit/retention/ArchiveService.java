package com.raghavendra.audit.retention;

import com.raghavendra.audit.amendment.domain.AuditAmendmentEntity;
import com.raghavendra.audit.amendment.domain.AuditAmendmentRepository;
import com.raghavendra.audit.common.hash.HexFormatUtil;
import com.raghavendra.audit.common.hash.ProtectedAmendmentProjection;
import com.raghavendra.audit.common.hash.Sha256Hasher;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventEntity;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.retention.domain.ArchiveManifestEntity;
import com.raghavendra.audit.retention.domain.ArchiveManifestRepository;
import com.raghavendra.audit.retention.domain.AuditEventArchiveEntity;
import com.raghavendra.audit.retention.domain.AuditEventArchiveRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

/**
 * Archives the oldest contiguous prefix of active events whose {@code eventTimestamp} is older
 * than a cutoff, moving them to the archive table.
 *
 * <p><strong>Atomic transaction (all-or-nothing), head-locked:</strong>
 * <ol>
 *   <li>lock the chain head {@code FOR UPDATE};</li>
 *   <li>select the oldest CONTIGUOUS prefix of active events with {@code event_timestamp < cutoff}
 *       (contiguity from sequence 1 upward — we never leave a hole in the active range);</li>
 *   <li>COPY those records into {@code audit_event_archive} (sequence, hashes, payload, and
 *       original timestamps preserved exactly) — copy BEFORE delete;</li>
 *   <li>create an {@code archive_manifest} binding the range under {@code manifest_hash};</li>
 *   <li>append an {@code ARCHIVE} amendment whose canonical detail embeds
 *       {@code {manifestId, manifestHash, fromSequence, toSequence, recordCount}} and advance the
 *       amendment head;</li>
 *   <li>DELETE the copied rows from {@code audit_event}.</li>
 * </ol>
 * Any failure rolls the whole thing back — no partial move, no orphan manifest/amendment.
 */
@Service
public class ArchiveService {

    public static final int SCHEMA_VERSION = 1;

    private final AuditEventRepository eventRepository;
    private final AuditEventArchiveRepository archiveRepository;
    private final ArchiveManifestRepository manifestRepository;
    private final AuditAmendmentRepository amendmentRepository;
    private final AuditChainHeadRepository chainHeadRepository;
    private final ArchiveManifestHasher manifestHasher;
    private final Sha256Hasher hasher;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();

    public ArchiveService(AuditEventRepository eventRepository,
                          AuditEventArchiveRepository archiveRepository,
                          ArchiveManifestRepository manifestRepository,
                          AuditAmendmentRepository amendmentRepository,
                          AuditChainHeadRepository chainHeadRepository,
                          ArchiveManifestHasher manifestHasher,
                          Sha256Hasher hasher,
                          Clock clock) {
        this.eventRepository = eventRepository;
        this.archiveRepository = archiveRepository;
        this.manifestRepository = manifestRepository;
        this.amendmentRepository = amendmentRepository;
        this.chainHeadRepository = chainHeadRepository;
        this.manifestHasher = manifestHasher;
        this.hasher = hasher;
        this.clock = clock;
    }

    /**
     * Archive the oldest contiguous prefix of active events older than {@code olderThan}.
     *
     * @return the created manifest
     * @throws ArchiveException if no eligible contiguous prefix exists
     */
    @Transactional
    public ArchiveManifestEntity archiveOlderThan(OffsetDateTime olderThan, String authorizedBy) {
        // Lock the head first — serializes archival with redaction and other amendment appends.
        AuditChainHeadEntity head = chainHeadRepository.findAndLockSingleton()
                .orElseThrow(() -> new IllegalStateException("chain head row missing"));

        // Oldest-first active events; take the leading run that is eligible (contiguous prefix).
        List<AuditEventEntity> active = eventRepository.findByOrderBySequenceNumberAsc();
        List<AuditEventEntity> toArchive = new java.util.ArrayList<>();
        for (AuditEventEntity e : active) {
            if (e.getEventTimestamp().isBefore(olderThan)) {
                toArchive.add(e);
            } else {
                break; // stop at the first non-eligible → contiguous oldest prefix only
            }
        }
        if (toArchive.isEmpty()) {
            throw new ArchiveException("No contiguous oldest prefix of events is older than the cutoff");
        }

        OffsetDateTime archivedAt = OffsetDateTime.now(clock)
                .withOffsetSameInstant(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
        long fromSeq = toArchive.get(0).getSequenceNumber();
        long toSeq = toArchive.get(toArchive.size() - 1).getSequenceNumber();
        long count = toArchive.size();
        byte[] firstHash = toArchive.get(0).getContentHash();
        byte[] lastHash = toArchive.get(toArchive.size() - 1).getContentHash();

        // COPY to archive BEFORE deleting anything active.
        for (AuditEventEntity e : toArchive) {
            archiveRepository.save(new AuditEventArchiveEntity(
                    e.getEventId(), e.getSequenceNumber(), e.getActorId(), e.getActorType(),
                    e.getAction(), e.getResourceType(), e.getResourceId(), e.getOutcome(),
                    e.getBusinessReason(), e.getEventTimestamp(), e.getRecordedAt(),
                    e.getSchemaVersion(), e.getPayload(), e.getPreviousHash(),
                    e.getContentHash(), archivedAt));
        }

        // Manifest.
        UUID manifestId = UUID.randomUUID();
        byte[] manifestHash = manifestHasher.hash(manifestId, fromSeq, toSeq, count,
                firstHash, lastHash, archivedAt, authorizedBy);
        ArchiveManifestEntity manifest = manifestRepository.save(new ArchiveManifestEntity(
                manifestId, fromSeq, toSeq, count, firstHash, lastHash, archivedAt,
                authorizedBy, manifestHash));

        // ARCHIVE amendment binding the manifest (no target_sequence_number for ARCHIVE).
        long nextAmendSeq = head.getLastAmendmentSeq() + 1;
        byte[] prevAmendHash = head.getAmendmentHeadHash();
        ObjectNode detail = mapper.createObjectNode();
        detail.put("manifestId", manifestId.toString());
        detail.put("manifestHash", HexFormatUtil.toLowerHex(manifestHash));
        detail.put("fromSequence", fromSeq);
        detail.put("toSequence", toSeq);
        detail.put("recordCount", count);
        String detailJson = detail.toString();

        UUID amendmentId = UUID.randomUUID();
        ProtectedAmendmentProjection projection = new ProtectedAmendmentProjection(
                SCHEMA_VERSION, nextAmendSeq, amendmentId.toString(), "ARCHIVE",
                null, detailJson, authorizedBy, archivedAt, prevAmendHash);
        byte[] amendContentHash = hasher.amendmentContentHash(projection);
        AuditAmendmentEntity amendment = new AuditAmendmentEntity(
                amendmentId, nextAmendSeq, "ARCHIVE", null, detailJson, authorizedBy,
                archivedAt, SCHEMA_VERSION, prevAmendHash, amendContentHash);
        amendmentRepository.save(amendment);
        head.advanceAmendment(nextAmendSeq, amendContentHash, archivedAt);
        chainHeadRepository.save(head);

        // DELETE the copied active rows LAST.
        eventRepository.deleteBySequenceRange(fromSeq, toSeq);

        return manifest;
    }
}
