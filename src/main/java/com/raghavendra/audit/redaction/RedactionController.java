package com.raghavendra.audit.redaction;

import com.raghavendra.audit.amendment.domain.AuditAmendmentEntity;
import com.raghavendra.audit.common.hash.HexFormatUtil;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Redaction API. {@code POST /api/v1/audit/events/{sequenceNumber}/redact} redacts one
 * declared-redactable payload field. ADMIN only (see SecurityConfig). The response echoes the
 * amendment that now backs the redaction.
 */
@RestController
@RequestMapping("/api/v1/audit/events/{sequenceNumber}/redact")
public class RedactionController {

    private final RedactionService redactionService;

    public RedactionController(RedactionService redactionService) {
        this.redactionService = redactionService;
    }

    public record RedactRequest(@NotBlank String field, String reason) {
    }

    public record RedactResponse(
            UUID amendmentId,
            long amendmentSeq,
            long targetSequenceNumber,
            String field,
            OffsetDateTime recordedAt,
            String amendmentContentHash
    ) {
    }

    @PostMapping
    public ResponseEntity<RedactResponse> redact(
            @PathVariable long sequenceNumber,
            @Valid @RequestBody RedactRequest request,
            java.security.Principal principal) {

        String actorId = principal != null ? principal.getName() : "unknown";
        AuditAmendmentEntity amendment =
                redactionService.redactField(sequenceNumber, request.field(), actorId);

        RedactResponse body = new RedactResponse(
                amendment.getAmendmentId(),
                amendment.getAmendmentSeq(),
                amendment.getTargetSequenceNumber(),
                request.field(),
                amendment.getRecordedAt(),
                HexFormatUtil.toLowerHex(amendment.getContentHash()));
        return ResponseEntity.ok(body);
    }
}
