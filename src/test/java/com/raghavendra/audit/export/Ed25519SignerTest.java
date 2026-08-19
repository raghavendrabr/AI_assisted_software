package com.raghavendra.audit.export;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Fail-closed key policy: an ephemeral dev key is allowed only under a local/test profile; a
 * deployed/default profile with no configured private key must fail startup.
 */
class Ed25519SignerTest {

    private static ExportSigningProperties noKey() {
        return new ExportSigningProperties(null, null, "kid");
    }

    @Test
    void noKey_underTestProfile_usesEphemeralDevKey() {
        var env = new MockEnvironment();
        env.setActiveProfiles("test");
        Ed25519Signer signer = new Ed25519Signer(noKey(), env);
        assertThat(signer.isEphemeralDevKey()).isTrue();
        assertThat(signer.publicKeyBase64()).isNotBlank();
    }

    @Test
    void noKey_underLocalProfile_usesEphemeralDevKey() {
        var env = new MockEnvironment();
        env.setActiveProfiles("local");
        assertThat(new Ed25519Signer(noKey(), env).isEphemeralDevKey()).isTrue();
    }

    @Test
    void noKey_deployedProfile_failsClosed() {
        var env = new MockEnvironment();
        env.setActiveProfiles("production"); // not local/test
        assertThatThrownBy(() -> new Ed25519Signer(noKey(), env))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Refusing to start");
    }

    @Test
    void noKey_noProfile_failsClosed() {
        // Default (no active profile) must also fail closed.
        assertThatThrownBy(() -> new Ed25519Signer(noKey(), new MockEnvironment()))
                .isInstanceOf(IllegalStateException.class);
    }
}
