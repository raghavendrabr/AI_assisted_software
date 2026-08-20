package com.raghavendra.audit.common.security;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Resolves an {@code X-API-Key} value to its role (and non-secret key id), server-side.
 *
 * <p>Keys are indexed by their SHA-256 digest; a presented key is matched by hashing it and
 * comparing digests with {@link MessageDigest#isEqual} (length-constant). Raw keys are not
 * retained in the lookup map.
 *
 * <p><strong>Key ids (auditability):</strong> each key has a stable, non-secret id used only in
 * sanitized auth logs (never the key or its digest). An id may be configured explicitly; when
 * absent, a synthetic id {@code <role>-key} is derived. Ids are validated at startup for safe
 * characters and bounded length, and duplicate ids are rejected — so a log line's key id
 * unambiguously identifies one configured key.
 *
 * <p><strong>Fail-fast configuration validation (at startup):</strong>
 * <ul>
 *   <li>whitespace-only / blank keys are treated as unset and skipped (allows unset env
 *       placeholders like {@code ${AUDIT_WRITER_KEY:}} to resolve to empty);</li>
 *   <li>a duplicated key (same non-empty value configured more than once) is rejected;</li>
 *   <li>the same key mapped to more than one role is rejected;</li>
 *   <li>a key id with unsafe characters or over the length bound is rejected;</li>
 *   <li>a duplicate key id (across entries) is rejected.</li>
 * </ul>
 *
 * <p><strong>Rotation / revocation:</strong> keys and their ids come from configuration. Rotating
 * or revoking a key therefore requires a <em>configuration update and an application
 * restart/reload</em> — there is no runtime revocation API in this prototype. This is documented in
 * ADR 0011 and the threat model.
 */
@Service
public class ApiKeyService {

    /** Allowed key-id characters and max length (safe for logs, filenames, references). */
    private static final Pattern KEY_ID_PATTERN = Pattern.compile("[A-Za-z0-9._-]+");
    private static final int MAX_KEY_ID_LEN = 64;

    /** Resolved principal for a valid key: its role and non-secret id. */
    public record ResolvedKey(ApiRole role, String keyId) {
    }

    private final Map<String, ResolvedKey> digestHexToKey = new HashMap<>();

    public ApiKeyService(ApiKeyProperties properties) {
        Set<String> seenKeyIds = new HashSet<>();
        for (ApiKeyProperties.ApiKeyEntry entry : properties.getApiKeys()) {
            String key = entry.getKey();
            ApiRole role = entry.getRole();

            // Whitespace-only / blank keys are treated as unset (skipped). Unset env
            // placeholders legitimately resolve to empty; those entries are simply inactive.
            if (key == null || key.isBlank()) {
                continue;
            }
            if (role == null) {
                throw new IllegalStateException(
                        "audit.security.api-keys: a configured API key has no role");
            }

            String keyId = resolveKeyId(entry, role);
            if (!seenKeyIds.add(keyId)) {
                // Do NOT include the key material; the id is non-secret and safe to name.
                throw new IllegalStateException(
                        "audit.security.api-keys: duplicate key id '" + keyId + "'");
            }

            String digest = sha256Hex(key);
            ResolvedKey existing = digestHexToKey.putIfAbsent(digest, new ResolvedKey(role, keyId));
            if (existing != null) {
                // Do NOT include the key or its digest in the message.
                if (existing.role() == role) {
                    throw new IllegalStateException(
                            "audit.security.api-keys: a duplicate API key is configured");
                }
                throw new IllegalStateException(
                        "audit.security.api-keys: the same API key is mapped to multiple roles");
            }
        }
    }

    private static String resolveKeyId(ApiKeyProperties.ApiKeyEntry entry, ApiRole role) {
        String id = entry.getId();
        if (id == null || id.isBlank()) {
            // Synthetic, stable, non-secret default when none is configured.
            return role.name().toLowerCase() + "-key";
        }
        id = id.trim();
        if (id.length() > MAX_KEY_ID_LEN) {
            throw new IllegalStateException(
                    "audit.security.api-keys: key id exceeds " + MAX_KEY_ID_LEN + " characters");
        }
        if (!KEY_ID_PATTERN.matcher(id).matches()) {
            throw new IllegalStateException(
                    "audit.security.api-keys: key id contains unsafe characters (allowed: "
                    + "letters, digits, '.', '_', '-')");
        }
        return id;
    }

    /** Resolve a presented key to its role + id, or empty if unknown/blank. */
    public Optional<ResolvedKey> resolve(String presentedKey) {
        if (presentedKey == null || presentedKey.isBlank()) {
            return Optional.empty();
        }
        String presentedDigest = sha256Hex(presentedKey);
        byte[] presentedBytes = presentedDigest.getBytes(StandardCharsets.UTF_8);
        for (Map.Entry<String, ResolvedKey> e : digestHexToKey.entrySet()) {
            if (MessageDigest.isEqual(e.getKey().getBytes(StandardCharsets.UTF_8), presentedBytes)) {
                return Optional.of(e.getValue());
            }
        }
        return Optional.empty();
    }

    /** Resolve a presented key to its role only (compatibility with existing callers). */
    public Optional<ApiRole> resolveRole(String presentedKey) {
        return resolve(presentedKey).map(ResolvedKey::role);
    }

    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
