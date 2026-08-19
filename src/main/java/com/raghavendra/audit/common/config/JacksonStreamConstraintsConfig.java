package com.raghavendra.audit.common.config;

import org.springframework.boot.jackson.autoconfigure.JsonFactoryBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.core.StreamReadConstraints;

/**
 * Applies {@link StreamReadConstraints} (maximum nesting depth, string length, and number length)
 * to the JSON factory Spring Boot uses to build the MVC request {@code ObjectMapper}.
 *
 * <p>This is intentionally a {@link JsonFactoryBuilderCustomizer} bean rather than a replacement
 * {@code ObjectMapper}: Boot's Jackson auto-configuration discovers the customizer and applies it
 * to the SAME factory that backs the request mapper, so all of Boot's other Jackson configuration
 * (modules, date handling, property naming, etc.) is preserved. A body that violates a constraint
 * fails during parsing, before a {@code JsonNode} is constructed; the resulting parse error is
 * mapped to a safe 400 by the API exception handler (no payload fragment is echoed).
 */
@Configuration
public class JacksonStreamConstraintsConfig {

    @Bean
    public JsonFactoryBuilderCustomizer auditStreamReadConstraintsCustomizer(
            HardeningProperties properties) {
        HardeningProperties.Limits limits = properties.getLimits();
        StreamReadConstraints constraints = StreamReadConstraints.builder()
                .maxNestingDepth(limits.getMaxJsonDepth())
                .maxStringLength(limits.getMaxJsonStringLength())
                .maxNumberLength(limits.getMaxJsonNumberLength())
                .build();
        return builder -> builder.streamReadConstraints(constraints);
    }
}
