package com.raghavendra.audit.common.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * TEMPORARY permissive security configuration.
 *
 * <p>{@code spring-boot-starter-security} is on the classpath (it will host the API-key +
 * role filter in a later step). Until that real authentication is implemented, this config
 * disables the default HTTP-Basic wall and CSRF so the write API is exercisable. It grants no
 * authorization guarantees and MUST be replaced by the API-key/role security in the security
 * step. Documented as an explicit, temporary boundary — not a silent gap.
 */
@Configuration
public class PermitAllSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}
