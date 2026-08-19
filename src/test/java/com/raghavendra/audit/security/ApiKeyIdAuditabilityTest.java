package com.raghavendra.audit.security;

import com.raghavendra.audit.common.security.ApiKeyProperties;
import com.raghavendra.audit.common.security.ApiKeyService;
import com.raghavendra.audit.common.security.ApiRole;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * API-key auditability: stable non-secret key ids, with startup validation for safe characters,
 * bounded length, and uniqueness. Ids are used only for sanitized logging; the key itself is never
 * exposed.
 */
class ApiKeyIdAuditabilityTest {

    private static ApiKeyProperties props(ApiKeyProperties.ApiKeyEntry... entries) {
        ApiKeyProperties p = new ApiKeyProperties();
        p.setApiKeys(List.of(entries));
        return p;
    }

    private static ApiKeyProperties.ApiKeyEntry entry(String key, ApiRole role, String id) {
        var e = new ApiKeyProperties.ApiKeyEntry();
        e.setKey(key);
        e.setRole(role);
        e.setId(id);
        return e;
    }

    @Test
    void explicitKeyId_isResolved() {
        ApiKeyService svc = new ApiKeyService(props(entry("k1", ApiRole.WRITER, "prod-writer-01")));
        assertThat(svc.resolve("k1")).isPresent();
        assertThat(svc.resolve("k1").get().keyId()).isEqualTo("prod-writer-01");
        assertThat(svc.resolve("k1").get().role()).isEqualTo(ApiRole.WRITER);
    }

    @Test
    void missingKeyId_getsSyntheticDefault() {
        ApiKeyService svc = new ApiKeyService(props(entry("k1", ApiRole.ADMIN, null)));
        assertThat(svc.resolve("k1").get().keyId()).isEqualTo("admin-key");
    }

    @Test
    void duplicateKeyIds_failStartup() {
        assertThatThrownBy(() -> new ApiKeyService(props(
                entry("k1", ApiRole.WRITER, "same-id"),
                entry("k2", ApiRole.ADMIN, "same-id"))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("duplicate key id");
    }

    @Test
    void unsafeCharacterKeyId_failsStartup() {
        assertThatThrownBy(() -> new ApiKeyService(props(
                entry("k1", ApiRole.WRITER, "bad id\nwith newline"))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("unsafe characters");
    }

    @Test
    void overlongKeyId_failsStartup() {
        String longId = "a".repeat(65); // > 64
        assertThatThrownBy(() -> new ApiKeyService(props(entry("k1", ApiRole.WRITER, longId))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("exceeds");
    }

    @Test
    void backwardCompatible_existingConfigWithoutIds_stillWorks() {
        // The current writer/reader/admin config (no ids) must keep working, each getting a
        // synthetic id and its role.
        ApiKeyService svc = new ApiKeyService(props(
                entry("w", ApiRole.WRITER, null),
                entry("c", ApiRole.COMPLIANCE_READER, null),
                entry("a", ApiRole.ADMIN, null)));
        assertThat(svc.resolve("w").get().keyId()).isEqualTo("writer-key");
        assertThat(svc.resolve("c").get().keyId()).isEqualTo("compliance_reader-key");
        assertThat(svc.resolve("a").get().keyId()).isEqualTo("admin-key");
    }
}
