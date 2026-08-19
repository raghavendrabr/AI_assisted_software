package com.raghavendra.audit.common.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

/**
 * Emits sanitized authentication-event log lines.
 *
 * <p><strong>Never logged:</strong>
 * <ul>
 *   <li>the API key, and the <strong>raw API-key SHA-256 digest is never logged</strong> either —
 *       the API-key principal is always the configured non-secret key id;</li>
 *   <li>the JWT (header/body/signature) or the full claims map;</li>
 *   <li><strong>arbitrary raw JWT subject text is not logged</strong> — a JWT identity is
 *       represented only by a bounded, stable <em>fingerprint</em> (a truncated SHA-256 of the
 *       subject, see {@link #jwtSubjectFingerprint}), never the untrusted subject string itself.</li>
 * </ul>
 *
 * <p>Only safe, bounded fields are recorded:
 * <ul>
 *   <li>the auth <em>method</em> (API_KEY / JWT / BOTH_REJECTED / NONE);</li>
 *   <li>the <em>result</em> (SUCCESS / FAILURE);</li>
 *   <li>a short, developer-authored <em>reason</em> constant;</li>
 *   <li>the <em>requestId</em> from MDC (correlation id; a filter is added in Commit C — until then
 *       it is simply absent);</li>
 *   <li>a non-secret <em>principal</em>: the stable API-key id, or the JWT-subject fingerprint.</li>
 * </ul>
 *
 * <p>All variable fields are passed through {@link #sanitize} to strip control characters and cap
 * length, preventing log-injection / forged log lines from untrusted input.
 */
@Component
public class AuthEventLogger {

    private static final Logger log = LoggerFactory.getLogger(AuthEventLogger.class);

    /** Max length for any sanitized field placed in a log line. */
    private static final int MAX_FIELD_LEN = 64;

    /** Length (hex chars) of the JWT-subject fingerprint. Short but collision-resistant enough. */
    private static final int FINGERPRINT_HEX_LEN = 16;

    public enum Method { API_KEY, JWT, BOTH_REJECTED, NONE }

    public enum Result { SUCCESS, FAILURE }

    /**
     * Log an authentication outcome.
     *
     * @param method    which mechanism was used/attempted
     * @param result    success or failure
     * @param reason    a short developer-authored constant (e.g. "valid-key", "invalid-token",
     *                  "both-credentials"); never derived from untrusted input
     * @param principal a non-secret identifier: an API-key ID or a JWT-subject fingerprint; may be
     *                  null when there is no safe principal to record
     */
    public void log(Method method, Result result, String reason, String principal) {
        String requestId = sanitize(MDC.get("requestId"));
        // Parameterized logging; every value is sanitized. No secret is ever passed in.
        if (result == Result.SUCCESS) {
            log.info("auth method={} result={} reason={} requestId={} principal={}",
                    method, result, sanitize(reason), requestId, sanitize(principal));
        } else {
            log.warn("auth method={} result={} reason={} requestId={} principal={}",
                    method, result, sanitize(reason), requestId, sanitize(principal));
        }
    }

    /**
     * A stable, non-reversible fingerprint of a JWT subject for logging: {@code jwt:<16 hex>} from a
     * SHA-256 of the subject. This lets the same subject be correlated across log lines WITHOUT ever
     * writing the raw (untrusted) subject text. Returns {@code "jwt:-"} for a null/blank subject.
     */
    public static String jwtSubjectFingerprint(String subject) {
        if (subject == null || subject.isBlank()) {
            return "jwt:-";
        }
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(subject.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder("jwt:");
            for (int i = 0; i < FINGERPRINT_HEX_LEN / 2; i++) {
                sb.append(Character.forDigit((d[i] >> 4) & 0xF, 16));
                sb.append(Character.forDigit(d[i] & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            return "jwt:-";
        }
    }

    /**
     * Strip control characters (including CR/LF, which enable log-forging) and bound length. Returns
     * {@code "-"} for null/blank so the field is always present and unambiguous.
     */
    public static String sanitize(String value) {
        if (value == null || value.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder(Math.min(value.length(), MAX_FIELD_LEN));
        for (int i = 0; i < value.length() && sb.length() < MAX_FIELD_LEN; i++) {
            char c = value.charAt(i);
            // Keep printable ASCII and common safe punctuation; replace anything else (control
            // chars, newlines, tabs, non-ASCII) with '_'.
            if (c >= 0x20 && c < 0x7F && c != '\n' && c != '\r') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        if (value.length() > MAX_FIELD_LEN) {
            sb.append("...");
        }
        return sb.toString();
    }
}
