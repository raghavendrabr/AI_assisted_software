package com.raghavendra.audit.common.security;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves an {@code X-API-Key} value to its role, server-side.
 *
 * <p>Keys are indexed by their SHA-256 digest; a presented key is matched by hashing it and
 * comparing digests with {@link MessageDigest#isEqual} (length-constant). Raw keys are not
 * retained in the lookup map.
 *
 * <p><strong>Fail-fast configuration validation (at startup):</strong>
 * <ul>
 *   <li>whitespace-only / blank keys are treated as unset and skipped (allows unset env
 *       placeholders like {@code ${AUDIT_WRITER_KEY:}} to resolve to empty);</li>
 *   <li>a duplicated key (same non-empty value configured more than once) is rejected;</li>
 *   <li>the same key mapped to more than one role is rejected.</li>
 * </ul>
 * The service never silently picks the "first matching" role for an ambiguous key — an
 * ambiguous configuration is a startup error.
 */
@Service
public class ApiKeyService {

    private final Map<String, ApiRole> digestHexToRole = new HashMap<>();

    public ApiKeyService(ApiKeyProperties properties) {
        // Track digest -> role to detect duplicates / multi-role conflicts without retaining
        // raw keys. A duplicate digest with a DIFFERENT role is a multi-role conflict; a
        // duplicate digest with the SAME role is a plain duplicate — both are rejected.
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

            String digest = sha256Hex(key);
            ApiRole existing = digestHexToRole.putIfAbsent(digest, role);
            if (existing != null) {
                // Do NOT include the key or its digest in the message.
                if (existing == role) {
                    throw new IllegalStateException(
                            "audit.security.api-keys: a duplicate API key is configured");
                }
                throw new IllegalStateException(
                        "audit.security.api-keys: the same API key is mapped to multiple roles");
            }
        }
    }

    /** Resolve a presented key to its role, or empty if unknown/blank. */
    public Optional<ApiRole> resolveRole(String presentedKey) {
        if (presentedKey == null || presentedKey.isBlank()) {
            return Optional.empty();
        }
        String presentedDigest = sha256Hex(presentedKey);
        byte[] presentedBytes = presentedDigest.getBytes(StandardCharsets.UTF_8);
        for (Map.Entry<String, ApiRole> e : digestHexToRole.entrySet()) {
            if (MessageDigest.isEqual(e.getKey().getBytes(StandardCharsets.UTF_8), presentedBytes)) {
                return Optional.of(e.getValue());
            }
        }
        return Optional.empty();
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
