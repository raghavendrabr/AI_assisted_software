package com.raghavendra.audit.common.hash;

/**
 * Lowercase hexadecimal encoding for hash bytes. Single deterministic representation used
 * wherever a hash must appear as text (canonical form, API responses, later export/verify).
 */
public final class HexFormatUtil {

    private HexFormatUtil() {
    }

    /** Encodes bytes as lowercase hex (2 chars per byte; 32 bytes → 64 chars). */
    public static String toLowerHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
