package com.raghavendra.audit.redaction;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for the redaction commitment: SecureRandom salt length, domain separation binding
 * (eventId + field path), and that no plaintext leaks into the stored hash-payload commitment.
 */
class RedactablePayloadProcessorTest {

    private final RedactablePayloadProcessor processor = new RedactablePayloadProcessor();
    private final ObjectMapper mapper = new ObjectMapper();

    private ObjectNode payload(String field, String value) {
        ObjectNode p = mapper.createObjectNode();
        p.put(field, value);
        return p;
    }

    @Test
    void salt_isAtLeast16Bytes() {
        var processed = processor.process("event-1", payload("acct", "123"), List.of("acct"));
        var stored = mapper.readTree(processed.storedPayloadJson());
        String saltHex = stored.get("acct").get("salt").asString();
        // 16 bytes -> 32 hex chars minimum. We use 32 bytes -> 64 hex chars.
        assertThat(saltHex.length()).isGreaterThanOrEqualTo(32);
        assertThat(saltHex.length()).isEqualTo(64);
    }

    @Test
    void commitment_rejectsShortSalt() {
        assertThatThrownBy(() -> processor.commitment("e", "f", new byte[8], mapper.valueToTree("v")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("16 bytes");
    }

    @Test
    void commitment_isBoundToEventId() {
        byte[] salt = new byte[16];
        var value = mapper.valueToTree("secret");
        String c1 = processor.commitment("event-A", "acct", salt, value);
        String c2 = processor.commitment("event-B", "acct", salt, value);
        // Same salt + value + field but different eventId → different commitment.
        assertThat(c1).isNotEqualTo(c2);
    }

    @Test
    void commitment_isBoundToFieldPath() {
        byte[] salt = new byte[16];
        var value = mapper.valueToTree("secret");
        String c1 = processor.commitment("event-A", "accountNumber", salt, value);
        String c2 = processor.commitment("event-A", "ssn", salt, value);
        assertThat(c1).isNotEqualTo(c2);
    }

    @Test
    void hashPayload_containsNoPlaintextValue() {
        var processed = processor.process("event-1", payload("acct", "SUPER_SECRET"), List.of("acct"));
        // The hash payload commits to salt+commitment only — the plaintext must not appear.
        assertThat(processed.hashPayloadJson()).doesNotContain("SUPER_SECRET");
        assertThat(processed.hashPayloadJson()).contains("salt").contains("commitment");
        // The STORED payload still holds the plaintext (until redacted).
        assertThat(processed.storedPayloadJson()).contains("SUPER_SECRET");
    }

    @Test
    void commitment_isNotReversible_plaintextAbsent() {
        byte[] salt = new byte[16];
        String commitment = processor.commitment("e", "f", salt, mapper.valueToTree("PLAINTEXT_X"));
        // A commitment is a hash; the plaintext must not be embedded in it.
        assertThat(commitment).doesNotContain("PLAINTEXT_X");
        assertThat(commitment).hasSize(64); // 32-byte SHA-256 as hex
    }
}
