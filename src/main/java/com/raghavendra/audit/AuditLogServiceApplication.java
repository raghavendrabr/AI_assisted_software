package com.raghavendra.audit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Application entry point for the tamper-evident audit log service.
 *
 * <p>Standard Spring Boot bootstrap. The application's behavior lives in the event, amendment,
 * redaction, retention, verify, export, compliance, and common modules.
 */
@SpringBootApplication
public class AuditLogServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuditLogServiceApplication.class, args);
    }
}
