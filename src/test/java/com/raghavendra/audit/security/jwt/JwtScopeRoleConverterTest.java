package com.raghavendra.audit.security.jwt;

import com.raghavendra.audit.common.security.jwt.JwtScopeRoleConverter;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the strict scope→role mapping: only trusted scopes grant authority; client-supplied
 * roles/authorities claims are ignored; there is no default role.
 */
class JwtScopeRoleConverterTest {

    private final JwtScopeRoleConverter converter = new JwtScopeRoleConverter(Map.of(
            "audit.write", "WRITER",
            "audit.read", "COMPLIANCE_READER",
            "audit.admin", "ADMIN"));

    private static Jwt jwtWithClaims(Map<String, Object> claims) {
        Jwt.Builder b = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .issuedAt(Instant.now().minusSeconds(60))
                .expiresAt(Instant.now().plusSeconds(600));
        claims.forEach(b::claim);
        return b.build();
    }

    private Collection<String> roles(Jwt jwt) {
        return converter.convert(jwt).stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
    }

    @Test
    void writeScope_mapsToWriterRole() {
        assertThat(roles(jwtWithClaims(Map.of("scope", "audit.write")))).containsExactly("ROLE_WRITER");
    }

    @Test
    void multipleScopes_mapToMultipleRoles() {
        assertThat(roles(jwtWithClaims(Map.of("scope", "audit.read audit.admin"))))
                .containsExactlyInAnyOrder("ROLE_COMPLIANCE_READER", "ROLE_ADMIN");
    }

    @Test
    void scpArrayClaim_isSupported() {
        assertThat(roles(jwtWithClaims(Map.of("scp", List.of("audit.write")))))
                .containsExactly("ROLE_WRITER");
    }

    @Test
    void unknownScopes_grantNothing() {
        assertThat(roles(jwtWithClaims(Map.of("scope", "openid profile some.other")))).isEmpty();
    }

    @Test
    void rolesAndAuthoritiesClaims_areIgnored() {
        // A client that stuffs roles/authorities but no trusted scope must get NO authority.
        assertThat(roles(jwtWithClaims(Map.of(
                "roles", List.of("ADMIN"),
                "authorities", List.of("ROLE_ADMIN"),
                "groups", List.of("admins"))))).isEmpty();
    }

    @Test
    void noScopeClaim_grantsNothing_noDefaultRole() {
        assertThat(roles(jwtWithClaims(Map.of("sub", "user-1")))).isEmpty();
    }
}
