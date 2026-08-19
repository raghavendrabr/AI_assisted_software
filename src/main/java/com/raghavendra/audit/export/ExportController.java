package com.raghavendra.audit.export;

import com.raghavendra.audit.event.api.InvalidSearchRequestException;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Bulk export API. {@code GET /api/v1/audit/export?resourceId=..} or {@code ?actorId=..} returns a
 * self-contained, Ed25519-signed bundle a recipient can verify offline. COMPLIANCE_READER (or
 * ADMIN). Exactly one of {@code resourceId} / {@code actorId} must be provided.
 */
@RestController
@RequestMapping("/api/v1/audit/export")
public class ExportController {

    private final ExportService exportService;

    public ExportController(ExportService exportService) {
        this.exportService = exportService;
    }

    @GetMapping
    public ResponseEntity<ExportBundle> export(
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String actorId) {

        boolean hasResource = resourceId != null && !resourceId.isBlank();
        boolean hasActor = actorId != null && !actorId.isBlank();
        if (hasResource == hasActor) { // both or neither
            throw new InvalidSearchRequestException(
                    "exactly one of 'resourceId' or 'actorId' must be provided");
        }

        ExportBundle bundle = hasResource
                ? exportService.export(ExportService.FilterType.RESOURCE_ID, resourceId)
                : exportService.export(ExportService.FilterType.ACTOR_ID, actorId);
        return ResponseEntity.ok(bundle);
    }

    /** Enables the export signing configuration properties. */
    @Configuration
    @EnableConfigurationProperties(ExportSigningProperties.class)
    static class ExportConfig {
    }
}
