package com.raghavendra.audit.common.hash;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Exposes the canonical serializer and SHA-256 hasher as Spring beans so the append service
 * (and later verify/export) can inject them.
 */
@Configuration
public class HashingConfig {

    @Bean
    public CanonicalJsonSerializer canonicalJsonSerializer() {
        return new CanonicalJsonSerializer();
    }

    @Bean
    public Sha256Hasher sha256Hasher(CanonicalJsonSerializer serializer) {
        return new Sha256Hasher(serializer);
    }
}
