package com.raghavendra.audit.common.security;

/**
 * The distinct API roles. These are capabilities, not a strict hierarchy: ADMIN is granted the
 * union of privileges explicitly in the security configuration rather than by inheritance.
 *
 * <ul>
 *   <li>{@code WRITER} — may append events (write API).</li>
 *   <li>{@code COMPLIANCE_READER} — may query events, verify the chain, and read compliance
 *       reports.</li>
 *   <li>{@code ADMIN} — administrative operations (reserved for redaction/retention in later
 *       steps); also granted the read/verify/compliance and write capabilities.</li>
 * </ul>
 */
public enum ApiRole {
    WRITER,
    COMPLIANCE_READER,
    ADMIN
}
