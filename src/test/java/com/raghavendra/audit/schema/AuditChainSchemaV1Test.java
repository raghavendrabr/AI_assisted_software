package com.raghavendra.audit.schema;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Schema-level integration test for the V1 Flyway migration.
 *
 * <p>Exercises the DATABASE contract directly via JDBC (no entities, repositories, or
 * services — those do not exist yet and are out of scope for this step). It verifies that
 * Flyway V1 applies cleanly, both tables and the singleton seed row exist, and every
 * CHECK / UNIQUE constraint behaves as designed.
 *
 * <p>Requires a running Docker engine (Testcontainers starts a throwaway PostgreSQL 16).
 */
@SpringBootTest
@Transactional // each test runs in a transaction that is rolled back → isolation between tests
class AuditChainSchemaV1Test {

    @TestConfiguration(proxyBeanMethods = false)
    static class PostgresTestContainerConfig {
        @Bean
        @ServiceConnection
        PostgreSQLContainer<?> postgresContainer() {
            return new PostgreSQLContainer<>("postgres:16");
        }
    }

    @Autowired
    private JdbcTemplate jdbc;

    // A valid 32-byte SHA-256 placeholder (content unimportant; length is what matters).
    private static byte[] hash32(int fill) {
        byte[] b = new byte[32];
        java.util.Arrays.fill(b, (byte) fill);
        return b;
    }

    private void insertEvent(long sequence, String eventId, byte[] previousHash, byte[] contentHash) {
        jdbc.update(
            "INSERT INTO audit_event (event_id, sequence_number, actor_id, actor_type, action, " +
            "resource_type, resource_id, outcome, event_timestamp, recorded_at, schema_version, " +
            "payload, previous_hash, content_hash) " +
            "VALUES (CAST(? AS uuid), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb), ?, ?)",
            eventId, sequence, "actor-1", "USER", "USER_LOGIN",
            "CLIENT_ACCOUNT", "acct-1", "SUCCESS", OffsetDateTime.now(), OffsetDateTime.now(), 1,
            "{}", previousHash, contentHash
        );
    }

    // ---- Flyway + structural expectations ---------------------------------------------

    @Test
    void flywayV1_isApplied_successfully() {
        Integer applied = jdbc.queryForObject(
            "SELECT count(*) FROM flyway_schema_history WHERE version = '1' AND success = true",
            Integer.class);
        assertThat(applied).isEqualTo(1);
    }

    @Test
    void bothTables_exist() {
        Integer tables = jdbc.queryForObject(
            "SELECT count(*) FROM information_schema.tables " +
            "WHERE table_schema = 'public' AND table_name IN ('audit_event','audit_chain_head')",
            Integer.class);
        assertThat(tables).isEqualTo(2);
    }

    @Test
    void chainHead_hasExactlyOneSeededEmptyRow() {
        Integer count = jdbc.queryForObject("SELECT count(*) FROM audit_chain_head", Integer.class);
        assertThat(count).isEqualTo(1);

        var row = jdbc.queryForMap("SELECT id, current_sequence, current_hash FROM audit_chain_head");
        assertThat(((Number) row.get("id")).intValue()).isEqualTo(1);
        assertThat(((Number) row.get("current_sequence")).longValue()).isEqualTo(0L);
        assertThat(row.get("current_hash")).isNull();
    }

    // ---- Valid inserts -----------------------------------------------------------------

    @Test
    void validGenesisEvent_isAccepted() {
        insertEvent(1, "11111111-1111-1111-1111-111111111111", null, hash32(1));
        Integer c = jdbc.queryForObject(
            "SELECT count(*) FROM audit_event WHERE sequence_number = 1", Integer.class);
        assertThat(c).isEqualTo(1);
    }

    @Test
    void validLaterEvent_isAccepted() {
        insertEvent(1, "22222222-2222-2222-2222-222222222222", null, hash32(1));
        insertEvent(2, "33333333-3333-3333-3333-333333333333", hash32(1), hash32(2));
        Integer c = jdbc.queryForObject(
            "SELECT count(*) FROM audit_event WHERE sequence_number = 2", Integer.class);
        assertThat(c).isEqualTo(1);
    }

    // ---- Constraint violations ---------------------------------------------------------

    @Test
    void invalidSequence_zeroOrNegative_isRejected() {
        assertThatThrownBy(() ->
            insertEvent(0, "44444444-4444-4444-4444-444444444444", null, hash32(1)))
            .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void invalidHashLength_contentHashNot32Bytes_isRejected() {
        byte[] shortHash = new byte[16];
        assertThatThrownBy(() ->
            insertEvent(1, "55555555-5555-5555-5555-555555555555", null, shortHash))
            .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void invalidPreviousHashRule_genesisWithPrevHash_isRejected() {
        // sequence 1 MUST have NULL previous_hash.
        assertThatThrownBy(() ->
            insertEvent(1, "66666666-6666-6666-6666-666666666666", hash32(9), hash32(1)))
            .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void invalidPreviousHashRule_laterEventWithoutPrevHash_isRejected() {
        // sequence > 1 MUST have a previous_hash.
        assertThatThrownBy(() ->
            insertEvent(2, "77777777-7777-7777-7777-777777777777", null, hash32(2)))
            .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void duplicateEventId_isRejected() {
        insertEvent(1, "88888888-8888-8888-8888-888888888888", null, hash32(1));
        assertThatThrownBy(() ->
            insertEvent(2, "88888888-8888-8888-8888-888888888888", hash32(1), hash32(2)))
            .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void duplicateSequenceNumber_isRejected() {
        insertEvent(1, "99999999-9999-9999-9999-999999999999", null, hash32(1));
        assertThatThrownBy(() ->
            insertEvent(1, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", null, hash32(3)))
            .isInstanceOf(DataIntegrityViolationException.class);
    }
}
