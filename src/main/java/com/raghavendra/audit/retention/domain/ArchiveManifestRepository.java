package com.raghavendra.audit.retention.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

/** Repository for archive manifests. Insert + read only. */
public interface ArchiveManifestRepository extends JpaRepository<ArchiveManifestEntity, UUID> {

    List<ArchiveManifestEntity> findAllByOrderByFromSequenceAsc();
}
