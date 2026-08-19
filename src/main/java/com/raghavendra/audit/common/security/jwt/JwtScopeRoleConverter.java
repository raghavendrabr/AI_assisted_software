package com.raghavendra.audit.common.security.jwt;

import com.raghavendra.audit.common.security.ApiRole;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps a validated JWT's <strong>trusted scopes</strong> to Spring Security {@code ROLE_*}
 * authorities.
 *
 * <p>Strict, fail-safe policy:
 * <ul>
 *   <li>Only scopes present in the configured {@code scopeRoles} map grant authority. Unknown
 *       scopes are ignored (grant nothing).</li>
 *   <li>Any {@code roles}/{@code authorities}/{@code groups} claim supplied by the client is
 *       <strong>ignored</strong> — authority is derived exclusively from mapped scopes, so a client
 *       cannot self-assign a role.</li>
 *   <li>There is <strong>no default role</strong>: a token with no mapped scope yields no
 *       authority, so the authorization matrix denies it (403).</li>
 * </ul>
 *
 * <p>Scopes are read from the standard {@code scope} claim (space-delimited string) or a
 * {@code scp} array claim, matching common authorization-server conventions.
 */
public class JwtScopeRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final Map<String, ApiRole> scopeToRole;

    public JwtScopeRoleConverter(Map<String, String> scopeRoles) {
        Map<String, ApiRole> resolved = new LinkedHashMap<>();
        scopeRoles.forEach((scope, roleName) -> {
            if (scope == null || scope.isBlank() || roleName == null) {
                return;
            }
            // A bad role name in configuration is a startup-time misconfiguration.
            resolved.put(scope, ApiRole.valueOf(roleName.trim()));
        });
        this.scopeToRole = Map.copyOf(resolved);
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String scope : extractScopes(jwt)) {
            ApiRole role = scopeToRole.get(scope);
            if (role != null) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name()));
            }
        }
        return authorities;
    }

    /** Read scopes from the {@code scope} (string) or {@code scp} (array) claims. Nothing else. */
    private static Collection<String> extractScopes(Jwt jwt) {
        Object scope = jwt.getClaim("scope");
        if (scope instanceof String s && !s.isBlank()) {
            return List.of(s.trim().split("\\s+"));
        }
        Object scp = jwt.getClaim("scp");
        if (scp instanceof Collection<?> c) {
            List<String> out = new ArrayList<>();
            for (Object o : c) {
                if (o instanceof String s && !s.isBlank()) {
                    out.add(s);
                }
            }
            return out;
        }
        return List.of();
    }
}
