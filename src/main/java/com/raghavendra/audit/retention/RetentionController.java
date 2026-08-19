package com.raghavendra.audit.retention;

import com.raghavendra.audit.retention.domain.ArchiveManifestEntity;
import com.raghavendra.audit.common.hash.HexFormatUtil;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Retention / archival API. {@code POST /api/v1/audit/retention/archive} archives the oldest
 * contiguous prefix of events older than a cutoff. ADMIN only (see SecurityConfig).
 */
@RestController
@RequestMapping("/api/v1/audit/retention/archive")
public class RetentionController {

    private final ArchiveService archiveService;

    public RetentionController(ArchiveService archiveService) {
        this.archiveService = archiveService;
    }

    public record ArchiveRequest(@NotNull OffsetDateTime olderThan) {
    }

    public record ArchiveResponse(
            UUID manifestId,
            long fromSequence,
            long toSequence,
            long recordCount,
            OffsetDateTime archivedAt,
            String authorizedBy,
            String manifestHash
    ) {
    }

    @PostMapping
    public ResponseEntity<ArchiveResponse> archive(
            @Valid @RequestBody ArchiveRequest request,
            java.security.Principal principal) {

        String authorizedBy = principal != null ? principal.getName() : "unknown";
        ArchiveManifestEntity m = archiveService.archiveOlderThan(request.olderThan(), authorizedBy);

        return ResponseEntity.ok(new ArchiveResponse(
                m.getManifestId(), m.getFromSequence(), m.getToSequence(), m.getRecordCount(),
                m.getArchivedAt(), m.getAuthorizedBy(), HexFormatUtil.toLowerHex(m.getManifestHash())));
    }
}
