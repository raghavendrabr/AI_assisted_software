package com.raghavendra.audit.common.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * API-key → role mappings, bound from configuration (environment / git-ignored local config;
 * never committed with real values).
 *
 * <p>Each entry maps a raw key to one role. The client sends only the key in {@code X-API-Key};
 * the role is resolved <strong>server-side</strong> — the client never supplies its own role.
 *
 * <p>Example (placeholders only, real keys via env):
 * <pre>
 * audit:
 *   security:
 *     api-keys:
 *       - key: ${AUDIT_WRITER_KEY}
 *         role: WRITER
 *       - key: ${AUDIT_COMPLIANCE_KEY}
 *         role: COMPLIANCE_READER
 *       - key: ${AUDIT_ADMIN_KEY}
 *         role: ADMIN
 * </pre>
 */
@ConfigurationProperties(prefix = "audit.security")
public class ApiKeyProperties {

    private List<ApiKeyEntry> apiKeys = List.of();

    public List<ApiKeyEntry> getApiKeys() {
        return apiKeys;
    }

    public void setApiKeys(List<ApiKeyEntry> apiKeys) {
        this.apiKeys = apiKeys;
    }

    /** A single key→role mapping, with an optional stable non-secret key id. */
    public static class ApiKeyEntry {
        private String key;
        private ApiRole role;
        /**
         * Stable, non-secret identifier for this key, used only in sanitized auth logs (never the
         * key or its digest). Enables operators to reference a key for rotation/revocation without
         * exposing it. Optional; when absent a synthetic id is derived from the role.
         */
        private String id;

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public ApiRole getRole() {
            return role;
        }

        public void setRole(ApiRole role) {
            this.role = role;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }
    }
}
