package com.raghavendra.audit.common;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Provides the system {@link Clock} used for server-assigned timestamps. Injecting a Clock
 * (rather than calling {@code OffsetDateTime.now()} directly) keeps the append service
 * testable and time deterministic where needed.
 */
@Configuration
public class TimeConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }
}
