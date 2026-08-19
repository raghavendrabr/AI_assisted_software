package com.raghavendra.audit.compliance;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Enables compliance configuration properties. */
@Configuration
@EnableConfigurationProperties(ComplianceProperties.class)
public class ComplianceConfig {
}
