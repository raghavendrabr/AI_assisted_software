package com.raghavendra.audit.retention.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.OffsetDateTime;
import java.util.UUID;

/** JPA mapping for {@code archive_manifest}: one row per archival operation. Immutable. */
@Entity
@Table(name = "archive_manifest")
public class ArchiveManifestEntity {

    @Id
    @Column(name = "manifest_id", nullable = false, updatable = false)
    private UUID manifestId;

    @Column(name = "from_sequence", nullable = false, updatable = false)
    private long fromSequence;

    @Column(name = "to_sequence", nullable = false, updatable = false)
    private long toSequence;

    @Column(name = "record_count", nullable = false, updatable = false)
    private long recordCount;

    @Column(name = "first_hash", nullable = false, updatable = false)
    private byte[] firstHash;

    @Column(name = "last_hash", nullable = false, updatable = false)
    private byte[] lastHash;

    @Column(name = "archived_at", nullable = false, updatable = false)
    private OffsetDateTime archivedAt;

    @Column(name = "authorized_by", nullable = false, updatable = false)
    private String authorizedBy;

    @Column(name = "manifest_hash", nullable = false, updatable = false)
    private byte[] manifestHash;

    protected ArchiveManifestEntity() {
    }

    public ArchiveManifestEntity(UUID manifestId, long fromSequence, long toSequence,
                                 long recordCount, byte[] firstHash, byte[] lastHash,
                                 OffsetDateTime archivedAt, String authorizedBy, byte[] manifestHash) {
        this.manifestId = manifestId;
        this.fromSequence = fromSequence;
        this.toSequence = toSequence;
        this.recordCount = recordCount;
        this.firstHash = firstHash.clone();
        this.lastHash = lastHash.clone();
        this.archivedAt = archivedAt;
        this.authorizedBy = authorizedBy;
        this.manifestHash = manifestHash.clone();
    }

    public UUID getManifestId() { return manifestId; }
    public long getFromSequence() { return fromSequence; }
    public long getToSequence() { return toSequence; }
    public long getRecordCount() { return recordCount; }
    public byte[] getFirstHash() { return firstHash.clone(); }
    public byte[] getLastHash() { return lastHash.clone(); }
    public OffsetDateTime getArchivedAt() { return archivedAt; }
    public String getAuthorizedBy() { return authorizedBy; }
    public byte[] getManifestHash() { return manifestHash.clone(); }
}
