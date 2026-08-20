package com.raghavendra.audit.security.jwt;

import com.raghavendra.audit.common.security.jwt.JwtProperties;
import com.raghavendra.audit.common.security.jwt.JwtSecurityConfig;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Conditional-activation and fail-fast behavior of the JWT configuration, exercised directly on the
 * {@link JwtProperties} / {@link JwtSecurityConfig} validation (no full context needed).
 */
class JwtConfigStartupTest {

    private static JwtProperties props(boolean enabled, String issuer, List<String> audiences) {
        JwtProperties p = new JwtProperties();
        p.setEnabled(enabled);
        p.setIssuerUri(issuer);
        p.setAudiences(audiences);
        return p;
    }

    @Test
    void disabled_isComplete_falseAndNotIncomplete() {
        JwtProperties p = props(false, null, List.of());
        assertThat(p.isComplete()).isFalse();
        assertThat(p.isEnabledButIncomplete()).isFalse();
        // validate() must not throw when disabled.
        assertThatCode(() -> new JwtSecurityConfig(p).validate()).doesNotThrowAnyException();
    }

    @Test
    void enabledButNoIssuerOrAudience_failsStartup() {
        JwtProperties p = props(true, null, List.of());
        assertThat(p.isEnabledButIncomplete()).isTrue();
        assertThatThrownBy(() -> new JwtSecurityConfig(p).validate())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("incomplete");
    }

    @Test
    void enabledWithIssuerButNoAudience_failsStartup() {
        JwtProperties p = props(true, "https://issuer.example", List.of());
        assertThat(p.isEnabledButIncomplete()).isTrue();
        assertThatThrownBy(() -> new JwtSecurityConfig(p).validate())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void enabledAndComplete_startsCleanly() {
        JwtProperties p = props(true, "https://issuer.example", List.of("aud-1"));
        assertThat(p.isComplete()).isTrue();
        assertThat(p.isEnabledButIncomplete()).isFalse();
        assertThatCode(() -> new JwtSecurityConfig(p).validate()).doesNotThrowAnyException();
    }
}
