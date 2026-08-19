package com.raghavendra.audit.security;

import com.raghavendra.audit.common.security.ApiKeyProperties;
import com.raghavendra.audit.common.security.ApiKeyService;
import com.raghavendra.audit.common.security.ApiRole;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Fail-fast configuration validation for API keys (unit-level, no Spring context).
 */
class ApiKeyServiceValidationTest {

    private static ApiKeyProperties props(ApiKeyProperties.ApiKeyEntry... entries) {
        ApiKeyProperties p = new ApiKeyProperties();
        p.setApiKeys(List.of(entries));
        return p;
    }

    private static ApiKeyProperties.ApiKeyEntry entry(String key, ApiRole role) {
        var e = new ApiKeyProperties.ApiKeyEntry();
        e.setKey(key);
        e.setRole(role);
        return e;
    }

    @Test
    void sameKeyMappedToMultipleRoles_failsFast() {
        assertThatThrownBy(() -> new ApiKeyService(props(
                entry("shared-key", ApiRole.WRITER),
                entry("shared-key", ApiRole.ADMIN))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("multiple roles")
                // The exception must NOT leak the key value.
                .hasMessageNotContaining("shared-key");
    }

    @Test
    void duplicateKeySameRole_failsFast() {
        assertThatThrownBy(() -> new ApiKeyService(props(
                entry("dup-key", ApiRole.WRITER),
                entry("dup-key", ApiRole.WRITER))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("duplicate")
                .hasMessageNotContaining("dup-key");
    }

    @Test
    void whitespaceOnlyKeys_areTreatedAsUnset_andSkipped() {
        // Blank/whitespace keys are skipped (not duplicates); a real key still resolves.
        ApiKeyService svc = new ApiKeyService(props(
                entry("   ", ApiRole.WRITER),
                entry("", ApiRole.COMPLIANCE_READER),
                entry("real-key", ApiRole.ADMIN)));
        assertThat(svc.resolveRole("real-key")).contains(ApiRole.ADMIN);
        assertThat(svc.resolveRole("   ")).isEmpty();
        assertThat(svc.resolveRole("")).isEmpty();
    }

    @Test
    void twoBlankKeysDifferentRoles_doNotConflict() {
        // Because blanks are skipped entirely, two unset placeholders must not be seen as a
        // multi-role conflict.
        assertThatCode(() -> new ApiKeyService(props(
                entry("  ", ApiRole.WRITER),
                entry("", ApiRole.ADMIN))))
                .doesNotThrowAnyException();
    }

    @Test
    void distinctKeysDistinctRoles_resolveCorrectly() {
        ApiKeyService svc = new ApiKeyService(props(
                entry("w", ApiRole.WRITER),
                entry("c", ApiRole.COMPLIANCE_READER),
                entry("a", ApiRole.ADMIN)));
        assertThat(svc.resolveRole("w")).contains(ApiRole.WRITER);
        assertThat(svc.resolveRole("c")).contains(ApiRole.COMPLIANCE_READER);
        assertThat(svc.resolveRole("a")).contains(ApiRole.ADMIN);
        assertThat(svc.resolveRole("unknown")).isEmpty();
    }
}
