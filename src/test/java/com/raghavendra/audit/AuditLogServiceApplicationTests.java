package com.raghavendra.audit;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.test.context.TestConfiguration;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Scaffolding-stage smoke test.
 *
 * <p>Default context-load check: it starts the full Spring application context against a REAL
 * PostgreSQL provided by Testcontainers, proving the wiring, datasource, JPA, and Flyway setup
 * boot successfully. Behavioral assertions live in the per-feature integration tests.
 *
 * <p>Requires a running Docker engine (Testcontainers starts a throwaway PostgreSQL 16
 * container). If Docker is not available the test cannot run.
 */
@SpringBootTest
class AuditLogServiceApplicationTests {

    @TestConfiguration(proxyBeanMethods = false)
    static class PostgresTestContainerConfig {

        /**
         * A throwaway PostgreSQL 16 container wired into the Spring context as the
         * datasource via {@link ServiceConnection}. Testcontainers 2.x coordinates:
         * {@code org.testcontainers:testcontainers-postgresql}.
         */
        @Bean
        @ServiceConnection
        PostgreSQLContainer<?> postgresContainer() {
            return new PostgreSQLContainer<>("postgres:16");
        }
    }

    @Test
    void contextLoads() {
        // Intentionally empty: success means the Spring context started against a real
        // PostgreSQL. Feature behavior is asserted in the per-feature integration tests.
    }
}
