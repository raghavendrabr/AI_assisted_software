package com.raghavendra.audit.export;

import com.raghavendra.audit.amendment.domain.AuditAmendmentRepository;
import com.raghavendra.audit.event.api.AppendEventRequest;
import com.raghavendra.audit.event.application.AuditEventAppendService;
import com.raghavendra.audit.event.domain.AuditChainHeadEntity;
import com.raghavendra.audit.event.domain.AuditChainHeadRepository;
import com.raghavendra.audit.event.domain.AuditEventRepository;
import com.raghavendra.audit.redaction.RedactionService;
import com.raghavendra.audit.retention.ArchiveService;
import com.raghavendra.audit.retention.domain.ArchiveManifestRepository;
import com.raghavendra.audit.retention.domain.AuditEventArchiveRepository;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Export + standalone verification: a signed bundle verifies offline; tampering with an event,
 * dropping/adding a record, reordering, or altering the manifest is rejected. Also exercises
 * archived + redacted events in the bundle.
 */
@SpringBootTest
@AbstractPostgresIntegrationTest.WithPostgres
class ExportIntegrationTest {

    @Autowired private AuditEventAppendService appendService;
    @Autowired private ExportService exportService;
    @Autowired private RedactionService redactionService;
    @Autowired private ArchiveService archiveService;
    @Autowired private AuditEventRepository eventRepository;
    @Autowired private AuditEventArchiveRepository archiveRepository;
    @Autowired private ArchiveManifestRepository manifestRepository;
    @Autowired private AuditAmendmentRepository amendmentRepository;
    @Autowired private AuditChainHeadRepository chainHeadRepository;

    private final ExportBundleVerifier verifier = new ExportBundleVerifier();

    @BeforeEach
    void reset() {
        amendmentRepository.deleteAll();
        manifestRepository.deleteAll();
        archiveRepository.deleteAll();
        eventRepository.deleteAll();
        chainHeadRepository.findById(AuditChainHeadEntity.SINGLETON_ID)
                .ifPresent(h -> { h.resetToEmpty(OffsetDateTime.now()); chainHeadRepository.save(h); });
    }

    private void append(String resourceId) {
        appendService.append(new AppendEventRequest(
                "CLIENT_ACCOUNT_VIEWED", "emp", "EMPLOYEE", "CLIENT_ACCOUNT", resourceId,
                "SUCCESS", null, null, null, null), UUID.randomUUID());
    }

    // ---- happy path --------------------------------------------------------------------

    @Test
    void export_producesSignedBundle_thatVerifiesOffline() {
        append("acct-1"); append("acct-1"); append("acct-2");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");

        assertThat(bundle.events()).hasSize(2);           // only acct-1
        assertThat(bundle.manifest().recordCount()).isEqualTo(2);
        assertThat(bundle.signatureBase64()).isNotBlank();
        assertThat(bundle.publicKeyBase64()).isNotBlank();

        assertThat(verifier.verify(bundle).valid()).isTrue();
    }

    @Test
    void export_withArchivedAndRedactedEvents_stillVerifies() {
        // A redactable event on acct-3, then archive it, then another active one.
        var payload = new tools.jackson.databind.ObjectMapper().createObjectNode();
        payload.put("accountNumber", "SECRET");
        long seq = appendService.append(new AppendEventRequest(
                "CLIENT_ACCOUNT_VIEWED", "emp", "EMPLOYEE", "CLIENT_ACCOUNT", "acct-3",
                "SUCCESS", null, payload, List.of("accountNumber"),
                OffsetDateTime.of(2026, 8, 1, 10, 0, 0, 0, ZoneOffset.UTC)), UUID.randomUUID())
                .getSequenceNumber();
        appendService.append(new AppendEventRequest(
                "CLIENT_ACCOUNT_VIEWED", "emp", "EMPLOYEE", "CLIENT_ACCOUNT", "acct-3",
                "SUCCESS", null, null, null,
                OffsetDateTime.of(2026, 8, 1, 10, 30, 0, 0, ZoneOffset.UTC)), UUID.randomUUID());
        redactionService.redactField(seq, "accountNumber", "admin");
        archiveService.archiveOlderThan(
                OffsetDateTime.of(2026, 8, 1, 10, 15, 0, 0, ZoneOffset.UTC), "admin"); // archives seq

        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-3");
        assertThat(bundle.events()).hasSize(2);
        assertThat(verifier.verify(bundle).valid()).isTrue();
    }

    // ---- tamper rejection --------------------------------------------------------------

    @Test
    void modifiedEvent_isRejected() {
        append("acct-1"); append("acct-1");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        ExportBundle tampered = withEvents(bundle, replaceActor(bundle.events(), 0, "attacker"));
        assertThat(verifier.verify(tampered).valid()).isFalse();
    }

    @Test
    void reorderedEvents_areRejected() {
        append("acct-1"); append("acct-1");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        List<ExportBundle.ExportedEvent> reversed = new ArrayList<>(bundle.events());
        java.util.Collections.reverse(reversed);
        assertThat(verifier.verify(withEvents(bundle, reversed)).valid()).isFalse();
    }

    @Test
    void removedEvent_isRejected() {
        append("acct-1"); append("acct-1");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        assertThat(verifier.verify(withEvents(bundle, bundle.events().subList(0, 1))).valid()).isFalse();
    }

    @Test
    void tamperedManifest_breaksSignature() {
        append("acct-1");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        ExportBundle.Manifest m = bundle.manifest();
        ExportBundle.Manifest tampered = new ExportBundle.Manifest(
                m.exportId(), m.exportedAt(), m.filterType(), "acct-EVIL", m.recordCount(),
                m.eventHashes(), m.amendmentHashes(), m.chainHead(), m.signingKeyId());
        ExportBundle badBundle = new ExportBundle(tampered, bundle.events(), bundle.amendments(),
                bundle.signatureBase64(), bundle.publicKeyBase64());
        assertThat(verifier.verify(badBundle).valid()).isFalse();
    }

    @Test
    void wrongPublicKey_isRejected() throws Exception {
        append("acct-1");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        // Verify against a DIFFERENT freshly-generated public key → must fail.
        var kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String otherPub = java.util.Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        assertThat(verifier.verify(bundle, otherPub).valid()).isFalse();
    }

    @Test
    void nonMatchingEventInjectedIntoFilteredBundle_isRejected() {
        append("acct-1");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        // Inject an event whose resourceId does NOT match the signed filter.
        var e = bundle.events().get(0);
        var evil = new ExportBundle.ExportedEvent(e.sequenceNumber() + 1, UUID.randomUUID().toString(),
                e.schemaVersion(), e.actorId(), e.actorType(), e.action(), e.resourceType(),
                "acct-OTHER", e.outcome(), e.businessReason(), e.eventTimestamp(), e.recordedAt(),
                e.payload(), e.previousHash(), e.contentHash(), e.archived());
        var events = new ArrayList<>(bundle.events());
        events.add(evil);
        assertThat(verifier.verify(withEvents(bundle, events)).valid()).isFalse();
    }

    @Test
    void duplicateEvent_isRejected() {
        append("acct-1");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        var events = new ArrayList<>(bundle.events());
        events.add(bundle.events().get(0)); // duplicate the same event
        assertThat(verifier.verify(withEvents(bundle, events)).valid()).isFalse();
    }

    @Test
    void modifiedAmendment_isRejected() {
        // Create a redacted event so the bundle carries a REDACTION amendment.
        long seq = appendRedactable("acct-1", "SECRET");
        redactionService.redactField(seq, "accountNumber", "admin");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        assertThat(bundle.amendments()).isNotEmpty();
        // Tamper the amendment's actor → recomputed hash won't match.
        var a = bundle.amendments().get(0);
        var tampered = new ExportBundle.ExportedAmendment(a.amendmentSeq(), a.amendmentId(),
                a.schemaVersion(), a.operation(), a.targetSequenceNumber(), a.detail(), "attacker",
                a.recordedAt(), a.previousAmendmentHash(), a.contentHash());
        var amendments = new ArrayList<ExportBundle.ExportedAmendment>();
        amendments.add(tampered);
        var bad = new ExportBundle(bundle.manifest(), bundle.events(), amendments,
                bundle.signatureBase64(), bundle.publicKeyBase64());
        assertThat(verifier.verify(bad).valid()).isFalse();
    }

    @Test
    void removedAmendment_isRejected() {
        long seq = appendRedactable("acct-1", "SECRET");
        redactionService.redactField(seq, "accountNumber", "admin");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        // Drop the amendment but keep the redacted (null) field → REDACTION_UNBACKED equivalent.
        var bad = new ExportBundle(bundle.manifest(), bundle.events(), List.of(),
                bundle.signatureBase64(), bundle.publicKeyBase64());
        assertThat(verifier.verify(bad).valid()).isFalse();
    }

    @Test
    void redactedValueWithoutItsAmendment_isRejected() {
        long seq = appendRedactable("acct-1", "SECRET");
        redactionService.redactField(seq, "accountNumber", "admin");
        ExportBundle bundle = exportService.export(ExportService.FilterType.RESOURCE_ID, "acct-1");
        // Keep events (with the null redacted field) but strip amendments AND their manifest hashes
        // so counts still line up — the redacted field then has no backing amendment.
        var m = bundle.manifest();
        var strippedManifest = new ExportBundle.Manifest(m.exportId(), m.exportedAt(), m.filterType(),
                m.filterValue(), m.recordCount(), m.eventHashes(), List.of(), m.chainHead(), m.signingKeyId());
        // NOTE: stripping breaks the signature; but the redaction-backing check runs regardless,
        // so verify must still be invalid (either signature or unbacked-redaction).
        var bad = new ExportBundle(strippedManifest, bundle.events(), List.of(),
                bundle.signatureBase64(), bundle.publicKeyBase64());
        assertThat(verifier.verify(bad).valid()).isFalse();
    }

    private long appendRedactable(String resourceId, String value) {
        var payload = new tools.jackson.databind.ObjectMapper().createObjectNode();
        payload.put("accountNumber", value);
        return appendService.append(new AppendEventRequest(
                "CLIENT_ACCOUNT_VIEWED", "emp", "EMPLOYEE", "CLIENT_ACCOUNT", resourceId,
                "SUCCESS", null, payload, List.of("accountNumber"), null), UUID.randomUUID())
                .getSequenceNumber();
    }

    // ---- helpers ------------------------------------------------------------------------

    private ExportBundle withEvents(ExportBundle b, List<ExportBundle.ExportedEvent> events) {
        return new ExportBundle(b.manifest(), events, b.amendments(), b.signatureBase64(), b.publicKeyBase64());
    }

    private List<ExportBundle.ExportedEvent> replaceActor(List<ExportBundle.ExportedEvent> events,
                                                          int idx, String actor) {
        List<ExportBundle.ExportedEvent> copy = new ArrayList<>(events);
        ExportBundle.ExportedEvent e = copy.get(idx);
        copy.set(idx, new ExportBundle.ExportedEvent(e.sequenceNumber(), e.eventId(), e.schemaVersion(),
                actor, e.actorType(), e.action(), e.resourceType(), e.resourceId(), e.outcome(),
                e.businessReason(), e.eventTimestamp(), e.recordedAt(), e.payload(),
                e.previousHash(), e.contentHash(), e.archived()));
        return copy;
    }
}
