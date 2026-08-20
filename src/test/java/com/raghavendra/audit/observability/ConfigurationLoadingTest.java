package com.raghavendra.audit.observability;

import com.raghavendra.audit.common.config.HardeningProperties;
import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the corrected configuration model: the test suite loads the MAIN
 * {@code application.yml} first and then applies {@code application-test.yml} overrides (because the
 * {@code test} profile is active). Concretely:
 * <ul>
 *   <li>a property defined ONLY in main {@code application.yml} remains loaded;</li>
 *   <li>a property overridden in {@code application-test.yml} wins over the main value;</li>
 *   <li>Actuator exposure + health configuration come from the MAIN configuration (not redefined by
 *       the test profile).</li>
 * </ul>
 */
@SpringBootTest
@AbstractPostgresIntegrationTest.WithPostgres
class ConfigurationLoadingTest {

    @Autowired
    private Environment env;

    @Autowired
    private HardeningProperties hardening;

    @Test
    void testProfileIsActive() {
        assertThat(env.getActiveProfiles()).contains("test");
    }

    @Test
    void mainOnlyProperty_remainsLoaded() {
        // These audit.limits values are defined ONLY in the MAIN application.yml (defaults 32 / 64)
        // and are NOT present in application-test.yml — so their bound presence proves main is
        // loaded. Bound via the resolved @ConfigurationProperties bean (authoritative).
        assertThat(hardening.getLimits().getMaxJsonDepth()).isEqualTo(32);
        assertThat(hardening.getLimits().getMaxRedactableFields()).isEqualTo(64);
    }

    @Test
    void testOverride_winsOverMainValue() {
        // main sets max-request-bytes=65536; application-test.yml overrides it to 4096.
        assertThat(hardening.getLimits().getMaxRequestBytes()).isEqualTo(4096);
    }

    @Test
    void actuatorExposureAndHealth_comeFromMainConfiguration() {
        // Exposure allow-list (health,info,prometheus) is defined in the MAIN application.yml and is
        // not redefined in application-test.yml.
        List<String> include = readExposureInclude();
        assertThat(include).contains("health", "info", "prometheus");
        assertThat(include).doesNotContain("env", "beans", "shutdown");

        // Health probes + readiness-includes-db come from main configuration.
        assertThat(env.getProperty("management.endpoint.health.probes.enabled", Boolean.class))
                .isTrue();
        assertThat(env.getProperty("management.endpoint.health.group.readiness.include"))
                .contains("db");
        assertThat(env.getProperty("management.endpoint.health.group.liveness.include"))
                .isEqualTo("livenessState");
        assertThat(env.getProperty("management.endpoint.health.show-details"))
                .isEqualTo("when-authorized");
    }

    /** Read the exposure include list, which binds either as a single csv value or indexed items. */
    private List<String> readExposureInclude() {
        String csv = env.getProperty("management.endpoints.web.exposure.include");
        if (csv != null && !csv.isBlank()) {
            return Arrays.stream(csv.split(",")).map(String::trim).toList();
        }
        // YAML list form binds as indexed properties.
        java.util.List<String> items = new java.util.ArrayList<>();
        for (int i = 0; ; i++) {
            String v = env.getProperty("management.endpoints.web.exposure.include[" + i + "]");
            if (v == null) {
                break;
            }
            items.add(v.trim());
        }
        return items;
    }
}
