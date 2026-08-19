package com.raghavendra.audit.redaction;

import com.raghavendra.audit.common.hash.HexFormatUtil;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;

/**
 * Transforms a raw payload into a redaction-ready form and computes what the hash commits to.
 *
 * <p>For each field named in {@code redactableFields}, the stored payload replaces the raw value
 * with an envelope {@code {"salt": <hex>, "commitment": <hex>, "value": <plaintext>}}. Crucially,
 * the string the CONTENT HASH commits to (the "hash payload") contains, for a redactable field,
 * only {@code {"salt", "commitment"}} — NOT the plaintext {@code value}. So later nulling the
 * plaintext on redaction leaves the hash input unchanged and the chain intact.
 *
 * <h2>Domain-separated commitment</h2>
 * The commitment is bound to a fixed domain tag, the event's public id, and the field path, so a
 * commitment can never be replayed for a different event or field:
 * <pre>
 *   commitment = SHA-256( "AUDIT_REDACT_v1" || 0x1F || eventId || 0x1F || fieldPath || 0x1F
 *                         || salt || canonical(value) )
 * </pre>
 * where {@code 0x1F} (unit separator) is an unambiguous domain/field delimiter and
 * {@code canonical(value)} is the value's compact JSON text. The salt is a fresh 32-byte
 * {@link SecureRandom} value (>= 16 bytes required).
 *
 * <p><strong>Limitation (documented, ADR 0007):</strong> retaining {@code salt} and
 * {@code commitment} makes a redacted LOW-ENTROPY value brute-forceable offline. This scheme
 * provides tamper-evidence, not confidentiality-at-rest.
 */
@Component
public class RedactablePayloadProcessor {

    /** Domain-separation tag; bump with any change to the commitment formula. */
    public static final String COMMITMENT_DOMAIN = "AUDIT_REDACT_v1";
    /** Unit-separator byte used as an unambiguous delimiter between commitment components. */
    private static final byte SEP = 0x1F;
    /** Minimum salt length (bytes). We use 32; the guard enforces the >= 16 requirement. */
    public static final int MIN_SALT_BYTES = 16;
    private static final int SALT_BYTES = 32;

    private final ObjectMapper mapper = new ObjectMapper();
    private final SecureRandom random = new SecureRandom();

    /** Result of processing: the payload to STORE, and the payload the HASH commits to. */
    public record Processed(String storedPayloadJson, String hashPayloadJson) {
    }

    /**
     * @param eventId          the event's public id (binds the commitment to this event)
     * @param rawPayload       the caller's payload object (may be null → treated as {})
     * @param redactableFields top-level field names to wrap as redactable (may be empty/null)
     */
    public Processed process(String eventId, JsonNode rawPayload, List<String> redactableFields) {
        ObjectNode source = (rawPayload != null && rawPayload.isObject())
                ? (ObjectNode) rawPayload.deepCopy()
                : mapper.createObjectNode();
        Set<String> redactable = redactableFields == null ? Set.of() : Set.copyOf(redactableFields);

        ObjectNode stored = mapper.createObjectNode();
        ObjectNode forHash = mapper.createObjectNode();

        for (String field : iterableNames(source)) {
            JsonNode value = source.get(field);
            if (redactable.contains(field)) {
                byte[] salt = new byte[SALT_BYTES];
                random.nextBytes(salt);
                String saltHex = HexFormatUtil.toLowerHex(salt);
                String commitmentHex = commitment(eventId, field, salt, value);

                ObjectNode storedEnvelope = mapper.createObjectNode();
                storedEnvelope.put("salt", saltHex);
                storedEnvelope.put("commitment", commitmentHex);
                storedEnvelope.set("value", value);
                stored.set(field, storedEnvelope);

                ObjectNode hashEnvelope = mapper.createObjectNode();
                hashEnvelope.put("salt", saltHex);
                hashEnvelope.put("commitment", commitmentHex);
                forHash.set(field, hashEnvelope);
            } else {
                stored.set(field, value);
                forHash.set(field, value);
            }
        }

        return new Processed(stored.toString(), forHash.toString());
    }

    /**
     * Recompute the "hash payload" from a STORED payload (verifier). Drops {@code value} from
     * redactable envelopes, keeping {@code salt, commitment}; other fields pass through. Yields
     * exactly what the content hash committed to — unchanged whether or not the value was redacted.
     */
    public String hashPayloadFromStored(String storedPayloadJson) {
        if (storedPayloadJson == null || storedPayloadJson.isBlank()) {
            return "{}";
        }
        JsonNode root = mapper.readTree(storedPayloadJson);
        if (!root.isObject()) {
            return storedPayloadJson;
        }
        ObjectNode forHash = mapper.createObjectNode();
        for (String field : iterableNames((ObjectNode) root)) {
            JsonNode v = root.get(field);
            if (isRedactableEnvelope(v)) {
                ObjectNode hashEnvelope = mapper.createObjectNode();
                hashEnvelope.set("salt", v.get("salt"));
                hashEnvelope.set("commitment", v.get("commitment"));
                forHash.set(field, hashEnvelope);
            } else {
                forHash.set(field, v);
            }
        }
        return forHash.toString();
    }

    /**
     * Domain-separated commitment bound to {@code eventId} and {@code fieldPath}:
     * {@code SHA-256(DOMAIN | eventId | fieldPath | salt | canonical(value))} with 0x1F
     * separators. A commitment therefore cannot be replayed for a different event or field.
     */
    public String commitment(String eventId, String fieldPath, byte[] salt, JsonNode value) {
        if (salt == null || salt.length < MIN_SALT_BYTES) {
            throw new IllegalArgumentException("salt must be at least " + MIN_SALT_BYTES + " bytes");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(COMMITMENT_DOMAIN.getBytes(StandardCharsets.UTF_8));
            md.update(SEP);
            md.update((eventId == null ? "" : eventId).getBytes(StandardCharsets.UTF_8));
            md.update(SEP);
            md.update((fieldPath == null ? "" : fieldPath).getBytes(StandardCharsets.UTF_8));
            md.update(SEP);
            md.update(salt);
            md.update(SEP);
            String canonicalValue = value == null || value.isNull() ? "null" : value.toString();
            md.update(canonicalValue.getBytes(StandardCharsets.UTF_8));
            return HexFormatUtil.toLowerHex(md.digest());
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private boolean isRedactableEnvelope(JsonNode n) {
        return n != null && n.isObject() && n.has("salt") && n.has("commitment");
    }

    private Iterable<String> iterableNames(ObjectNode node) {
        List<String> names = new java.util.ArrayList<>();
        node.propertyNames().forEach(names::add);
        return names;
    }
}
