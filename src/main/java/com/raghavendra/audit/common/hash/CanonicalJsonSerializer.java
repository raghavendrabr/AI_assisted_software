package com.raghavendra.audit.common.hash;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Deterministic canonical serializer for the {@link ProtectedEventProjection}.
 *
 * <p>Produces a single, stable string for a given logical event so that logically-identical
 * events always hash identically, regardless of incidental encoding differences. This is the
 * input to {@link Sha256Hasher}. It does <strong>not</strong> rely on Jackson's default
 * serialization order — Jackson is used only to parse the payload into a tree, which is then
 * re-emitted by this class's own deterministic writer.
 *
 * <h2>Canonicalization rules</h2>
 * <ul>
 *   <li><b>Fixed top-level field order.</b> The protected fields are emitted in the exact
 *       order declared by {@link ProtectedEventProjection}; the projection's field order is
 *       the canonical order (it does not depend on any map/reflection ordering).</li>
 *   <li><b>Object keys sorted.</b> Within the JSON payload, every object's keys are sorted
 *       lexicographically by Java {@code String.compareTo} (UTF-16 code-unit order), applied
 *       recursively. Array element order is preserved (arrays are ordered by definition).</li>
 *   <li><b>UTF-8.</b> The canonical form is a Java {@code String}; {@link Sha256Hasher}
 *       hashes its UTF-8 bytes. All characters are represented via JSON string escaping.</li>
 *   <li><b>Explicit nulls.</b> A null protected field is emitted as the JSON token
 *       {@code null} (never omitted), so presence/absence cannot be confused.</li>
 *   <li><b>Timestamp normalization (PostgreSQL-safe).</b> {@link OffsetDateTime} values are
 *       converted to UTC and <b>truncated to microsecond precision</b>, then formatted with a
 *       single fixed pattern (ISO-8601, {@code 'Z'} suffix, exactly <b>6</b> fractional
 *       digits). PostgreSQL {@code TIMESTAMPTZ} stores microseconds, so hashing at microsecond
 *       precision guarantees the canonical form is unchanged after a persist/reread round-trip.
 *       Any sub-microsecond (nanosecond) component is dropped <i>before</i> hashing. Equal
 *       instants in different offsets canonicalize identically. The append service MUST persist
 *       the same microsecond-truncated instant it hashed.</li>
 *   <li><b>No insignificant whitespace.</b> The output contains no spacing or newlines
 *       beyond what is inside string values.</li>
 * </ul>
 *
 * <p>The output is a JSON-shaped object with fixed keys. The keys themselves are fixed
 * literals in this class (also sorted, for consistency), so the whole structure is stable.
 */
public final class CanonicalJsonSerializer {

    /**
     * Fixed UTC timestamp format: ISO-8601 date-time with a literal {@code Z} zone and exactly
     * SIX fractional digits (microseconds). Values are truncated to microseconds before
     * formatting, matching PostgreSQL {@code TIMESTAMPTZ} precision so the canonical form
     * survives a persist/reread round-trip unchanged.
     */
    private static final DateTimeFormatter UTC_FORMAT =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'");

    private final ObjectMapper objectMapper;

    public CanonicalJsonSerializer() {
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Serialize the protected projection into its canonical string form.
     *
     * @param p the protected projection (must not be null)
     * @return the canonical string; feed its UTF-8 bytes to {@link Sha256Hasher}
     */
    public String canonicalize(ProtectedEventProjection p) {
        // Top-level fields are emitted in a FIXED, explicit order. We build the string
        // directly rather than through a Map so ordering can never depend on map iteration.
        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        writeLiteralField(sb, "schemaVersion", Integer.toString(p.schemaVersion()));
        writeSep(sb);
        writeLiteralField(sb, "sequenceNumber", Long.toString(p.sequenceNumber()));
        writeSep(sb);
        writeStringField(sb, "eventId", p.eventId());
        writeSep(sb);
        writeStringField(sb, "actorId", p.actorId());
        writeSep(sb);
        writeStringField(sb, "actorType", p.actorType());
        writeSep(sb);
        writeStringField(sb, "action", p.action());
        writeSep(sb);
        writeStringField(sb, "resourceType", p.resourceType());
        writeSep(sb);
        writeStringField(sb, "resourceId", p.resourceId());
        writeSep(sb);
        writeStringField(sb, "outcome", p.outcome());
        writeSep(sb);
        writeStringField(sb, "businessReason", p.businessReason()); // null -> null token
        writeSep(sb);
        writeStringField(sb, "eventTimestamp", formatTimestamp(p.eventTimestamp()));
        writeSep(sb);
        writeStringField(sb, "recordedAt", formatTimestamp(p.recordedAt()));
        writeSep(sb);
        // payload is emitted as canonicalized JSON (keys sorted recursively).
        writeRawField(sb, "payload", canonicalizePayload(p.payloadJson()));
        writeSep(sb);
        // previousHash: 32-byte hash rendered as exactly 64 lowercase hex chars, or null token.
        writeStringField(sb, "previousHash", hexOrNull(p.previousHash()));
        sb.append('}');
        return sb.toString();
    }

    // ---- payload canonicalization ------------------------------------------------------

    /**
     * Parse the payload JSON and re-emit it with all object keys sorted recursively.
     * A null or blank payload canonicalizes to an empty object {@code {}} so that "no
     * payload" is represented consistently.
     */
    private String canonicalizePayload(String payloadJson) {
        if (payloadJson == null || payloadJson.isBlank()) {
            return "{}";
        }
        JsonNode root = objectMapper.readTree(payloadJson);
        StringBuilder sb = new StringBuilder();
        writeCanonicalNode(sb, root);
        return sb.toString();
    }

    /** Recursively writes a JSON node with object keys sorted; array order preserved. */
    private void writeCanonicalNode(StringBuilder sb, JsonNode node) {
        if (node == null || node.isNull()) {
            sb.append("null");
            return;
        }
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            List<String> keys = new ArrayList<>();
            for (Map.Entry<String, JsonNode> e : obj.properties()) {
                keys.add(e.getKey());
            }
            keys.sort(String::compareTo); // UTF-16 code-unit order, documented
            sb.append('{');
            boolean first = true;
            for (String k : keys) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeJsonString(sb, k);
                sb.append(':');
                writeCanonicalNode(sb, obj.get(k));
            }
            sb.append('}');
        } else if (node.isArray()) {
            ArrayNode arr = (ArrayNode) node;
            sb.append('[');
            for (int i = 0; i < arr.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                writeCanonicalNode(sb, arr.get(i));
            }
            sb.append(']');
        } else if (node.isTextual()) {
            writeJsonString(sb, node.asString());
        } else if (node.isBoolean()) {
            sb.append(node.asBoolean() ? "true" : "false");
        } else {
            // Numbers: use the node's canonical numeric text as parsed.
            sb.append(node.decimalValue().stripTrailingZeros().toPlainString());
        }
    }

    // ---- timestamp normalization -------------------------------------------------------

    private String formatTimestamp(OffsetDateTime ts) {
        if (ts == null) {
            return null;
        }
        // Convert to UTC, then truncate to microseconds so we never hash precision that
        // PostgreSQL TIMESTAMPTZ cannot persist (it stores microseconds, not nanoseconds).
        return ts.withOffsetSameInstant(ZoneOffset.UTC)
                 .truncatedTo(ChronoUnit.MICROS)
                 .format(UTC_FORMAT);
    }

    // ---- previousHash encoding ---------------------------------------------------------

    /**
     * Renders a 32-byte hash as exactly 64 lowercase hex characters, or returns {@code null}
     * for the genesis record. This is the single deterministic representation of previousHash
     * inside the canonical form. (Length is guaranteed 32 by {@link ProtectedEventProjection}.)
     */
    private String hexOrNull(byte[] hash) {
        return hash == null ? null : HexFormatUtil.toLowerHex(hash);
    }

    // ---- low-level JSON writing --------------------------------------------------------

    private void writeSep(StringBuilder sb) {
        sb.append(',');
    }

    /** Writes {@code "key":"value"} with value JSON-escaped, or {@code "key":null}. */
    private void writeStringField(StringBuilder sb, String key, String value) {
        writeJsonString(sb, key);
        sb.append(':');
        if (value == null) {
            sb.append("null");
        } else {
            writeJsonString(sb, value);
        }
    }

    /** Writes {@code "key":rawValue} where rawValue is already valid JSON (no quoting). */
    private void writeRawField(StringBuilder sb, String key, String rawValue) {
        writeJsonString(sb, key);
        sb.append(':');
        sb.append(rawValue);
    }

    /** Writes {@code "key":literal} where literal is a raw numeric/boolean token. */
    private void writeLiteralField(StringBuilder sb, String key, String literal) {
        writeJsonString(sb, key);
        sb.append(':');
        sb.append(literal);
    }

    /**
     * Writes a JSON string literal with standard escaping (RFC 8259): quotes, backslash,
     * control characters, and the required short escapes. Non-ASCII characters are emitted
     * as-is (they become UTF-8 bytes at hash time), which is valid JSON.
     */
    private void writeJsonString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
