package com.raghavendra.audit.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.containers.PostgreSQLContainer;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Shared Testcontainers PostgreSQL 16 wiring for integration tests. Import via
 * {@code @Import(AbstractPostgresIntegrationTest.PostgresContainerConfig.class)} or use the
 * convenience {@link WithPostgres} meta-annotation.
 */
public final class AbstractPostgresIntegrationTest {

    private AbstractPostgresIntegrationTest() {
    }

    @TestConfiguration(proxyBeanMethods = false)
    public static class PostgresContainerConfig {
        @Bean
        @ServiceConnection
        public PostgreSQLContainer<?> postgresContainer() {
            return new PostgreSQLContainer<>("postgres:16");
        }
    }

    /**
     * Meta-annotation that imports the shared PostgreSQL container config AND activates the
     * {@code test} profile — so every integration test consistently loads the main
     * {@code application.yml} and then applies {@code application-test.yml} overrides, without each
     * test repeating {@code @ActiveProfiles}. (The two non-Postgres {@code @SpringBootTest} classes
     * declare {@code @ActiveProfiles("test")} directly.)
     */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @Import(PostgresContainerConfig.class)
    @ActiveProfiles("test")
    public @interface WithPostgres {
    }
}
