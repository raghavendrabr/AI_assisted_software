package com.raghavendra.audit.compliance;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for compliance reporting (Scenario C in-scope slice).
 *
 * @param clientAccountResourceType the {@code resourceType} value that denotes client-account
 *        data; the access report is scoped to events with this resource type.
 */
@ConfigurationProperties(prefix = "audit.compliance")
public record ComplianceProperties(String clientAccountResourceType) {

    public ComplianceProperties {
        if (clientAccountResourceType == null || clientAccountResourceType.isBlank()) {
            clientAccountResourceType = "CLIENT_ACCOUNT";
        }
    }
}
