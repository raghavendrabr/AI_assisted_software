package com.raghavendra.audit.security;

import com.raghavendra.audit.common.security.AuthEventLogger;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the sanitized-field logic used by {@link AuthEventLogger}. Guards against
 * log-injection (CR/LF and control characters) and bounds field length.
 */
class AuthEventLoggerTest {

    @Test
    void newlineAndCarriageReturn_areStripped() {
        String input = "abc" + '\r' + '\n' + "INJECTED";
        String out = AuthEventLogger.sanitize(input);
        assertThat(out).doesNotContain("\n").doesNotContain("\r");
        assertThat(out).contains("abc").contains("INJECTED"); // content kept, control chars removed
    }

    @Test
    void controlCharacters_areReplaced() {
        String input = "a" + '\t' + "bc"; // tab between 'a' and 'bc'
        String out = AuthEventLogger.sanitize(input);
        assertThat(out).doesNotContain("\t");
        assertThat(out).isEqualTo("a_bc"); // the non-printable tab becomes '_'
    }

    @Test
    void nullOrEmpty_becomeDash() {
        assertThat(AuthEventLogger.sanitize(null)).isEqualTo("-");
        assertThat(AuthEventLogger.sanitize("")).isEqualTo("-");
    }

    @Test
    void overlongValue_isTruncated() {
        String out = AuthEventLogger.sanitize("x".repeat(500));
        assertThat(out.length()).isLessThanOrEqualTo(64 + 3); // bounded + ellipsis
        assertThat(out).endsWith("...");
    }

    @Test
    void safeValue_passesThroughUnchanged() {
        assertThat(AuthEventLogger.sanitize("prod-writer-01")).isEqualTo("prod-writer-01");
    }

    // ---- JWT subject fingerprint (never the raw subject) --------------------------------

    @Test
    void jwtFingerprint_doesNotContainRawSubject_andIsStable() {
        String subject = "user-1234-very-identifying-subject";
        String fp1 = AuthEventLogger.jwtSubjectFingerprint(subject);
        String fp2 = AuthEventLogger.jwtSubjectFingerprint(subject);
        assertThat(fp1).startsWith("jwt:");
        assertThat(fp1).doesNotContain(subject);      // the raw subject text is never present
        assertThat(fp1).isEqualTo(fp2);               // stable for the same subject
        assertThat(fp1.length()).isLessThanOrEqualTo("jwt:".length() + 16);
    }

    @Test
    void jwtFingerprint_differsForDifferentSubjects() {
        assertThat(AuthEventLogger.jwtSubjectFingerprint("a"))
                .isNotEqualTo(AuthEventLogger.jwtSubjectFingerprint("b"));
    }

    @Test
    void jwtFingerprint_nullOrBlank_isDashSentinel() {
        assertThat(AuthEventLogger.jwtSubjectFingerprint(null)).isEqualTo("jwt:-");
        assertThat(AuthEventLogger.jwtSubjectFingerprint("  ")).isEqualTo("jwt:-");
    }
}
