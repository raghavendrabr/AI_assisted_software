package com.raghavendra.audit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Application entry point for the tamper-evident audit log service.
 *
 * <p>Scaffolding stage: this is the minimal Spring Boot bootstrap only. No entities,
 * repositories, controllers, services, migrations, or business logic exist yet — those
 * are added in later steps of the implementation plan.
 */
@SpringBootApplication
public class AuditLogServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuditLogServiceApplication.class, args);
    }
}
