package com.raghavendra.audit.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Request/security hardening knobs (Commit A).
 *
 * <p>Two independent groups, bound under {@code audit}:
 * <ul>
 *   <li>{@code audit.limits.*} — request-body and JSON-parsing bounds that cap resource use
 *       before an event is parsed/persisted (defense against oversized or maliciously-nested
 *       bodies). The raw byte cap is enforced by a streaming filter; the JSON depth/string/number
 *       bounds are enforced by Jackson {@code StreamReadConstraints} on the request mapper.</li>
 *   <li>{@code audit.docs.*} — whether the OpenAPI/Swagger surface is served at all and, if so,
 *       whether it is public. Defaults are closed: not public, and (outside {@code local}) not
 *       enabled. This is wired to BOTH springdoc enablement and the security matrix.</li>
 * </ul>
 *
 * <p>All values have safe defaults so the service behaves identically to before unless explicitly
 * reconfigured, except that the docs surface is no longer public by default.
 */
@ConfigurationProperties(prefix = "audit")
public class HardeningProperties {

    private final Limits limits = new Limits();
    private final Docs docs = new Docs();

    public Limits getLimits() {
        return limits;
    }

    public Docs getDocs() {
        return docs;
    }

    /**
     * Request-body and JSON-parse bounds. Defaults chosen to comfortably fit legitimate audit
     * events while rejecting pathological bodies well before they can exhaust memory or CPU.
     */
    public static class Limits {
        /** Maximum accepted request-body size in bytes for write endpoints. Default 64 KiB. */
        private int maxRequestBytes = 64 * 1024;
        /** Maximum JSON nesting depth accepted by the request mapper. Default 32. */
        private int maxJsonDepth = 32;
        /** Maximum length of any single JSON string value. Default 65,536 characters. */
        private int maxJsonStringLength = 65_536;
        /** Maximum length of any single JSON number token. Default 128 characters. */
        private int maxJsonNumberLength = 128;
        /** Maximum number of entries allowed in {@code redactableFields}. Default 64. */
        private int maxRedactableFields = 64;
        /** Maximum length of a single redactable field-path. Default 128 characters. */
        private int maxRedactableFieldPathLength = 128;

        public int getMaxRequestBytes() {
            return maxRequestBytes;
        }

        public void setMaxRequestBytes(int maxRequestBytes) {
            this.maxRequestBytes = maxRequestBytes;
        }

        public int getMaxJsonDepth() {
            return maxJsonDepth;
        }

        public void setMaxJsonDepth(int maxJsonDepth) {
            this.maxJsonDepth = maxJsonDepth;
        }

        public int getMaxJsonStringLength() {
            return maxJsonStringLength;
        }

        public void setMaxJsonStringLength(int maxJsonStringLength) {
            this.maxJsonStringLength = maxJsonStringLength;
        }

        public int getMaxJsonNumberLength() {
            return maxJsonNumberLength;
        }

        public void setMaxJsonNumberLength(int maxJsonNumberLength) {
            this.maxJsonNumberLength = maxJsonNumberLength;
        }

        public int getMaxRedactableFields() {
            return maxRedactableFields;
        }

        public void setMaxRedactableFields(int maxRedactableFields) {
            this.maxRedactableFields = maxRedactableFields;
        }

        public int getMaxRedactableFieldPathLength() {
            return maxRedactableFieldPathLength;
        }

        public void setMaxRedactableFieldPathLength(int maxRedactableFieldPathLength) {
            this.maxRedactableFieldPathLength = maxRedactableFieldPathLength;
        }
    }

    /**
     * OpenAPI/Swagger exposure. Fail-closed defaults: NOT public; enablement left to configuration
     * (the {@code local} profile turns it on and makes it public). When {@code enabled=true} and
     * {@code public=false}, the docs require ADMIN.
     */
    public static class Docs {
        /** Whether the OpenAPI/Swagger endpoints are served at all. Default false. */
        private boolean enabled = false;
        /** Whether the (enabled) docs are reachable without authentication. Default false. */
        private boolean isPublic = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /** Bound from {@code audit.docs.public}. */
        public boolean isPublic() {
            return isPublic;
        }

        public void setPublic(boolean isPublic) {
            this.isPublic = isPublic;
        }
    }
}
