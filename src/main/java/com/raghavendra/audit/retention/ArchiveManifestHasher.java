package com.raghavendra.audit.retention;

import com.raghavendra.audit.common.hash.HexFormatUtil;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * Computes the canonical manifest hash that binds an archival operation.
 *
 * <p><strong>Length-prefixed encoding (unambiguous):</strong> every component is fed as its
 * UTF-8 bytes preceded by an 8-byte big-endian length. Because each field's length is committed
 * before its bytes, no delimiter is needed and no field's content can be confused with a
 * boundary — even a value containing arbitrary bytes cannot forge a different field layout.
 * <pre>
 *   manifest_hash = SHA-256(
 *       lp("AUDIT_ARCHIVE_MANIFEST_v1") | lp(manifestId) | lp(fromSequence) | lp(toSequence) |
 *       lp(recordCount) | lp(hex(firstHash)) | lp(hex(lastHash)) | lp(archivedAt UTC µs) |
 *       lp(authorizedBy) )
 *   where lp(x) = int64_be(len(utf8(x))) || utf8(x)
 * </pre>
 * The ARCHIVE amendment then binds this {@code manifest_hash} (plus the range/count) into the
 * amendment chain. firstHash/lastHash are the content hashes of the first/last archived record.
 */
@Component
public class ArchiveManifestHasher {

    public static final String DOMAIN = "AUDIT_ARCHIVE_MANIFEST_v1";
    private static final DateTimeFormatter UTC_FORMAT =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'");

    public byte[] hash(UUID manifestId, long fromSequence, long toSequence, long recordCount,
                       byte[] firstHash, byte[] lastHash, OffsetDateTime archivedAt,
                       String authorizedBy) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            put(md, DOMAIN);
            put(md, manifestId.toString());
            put(md, Long.toString(fromSequence));
            put(md, Long.toString(toSequence));
            put(md, Long.toString(recordCount));
            put(md, HexFormatUtil.toLowerHex(firstHash));
            put(md, HexFormatUtil.toLowerHex(lastHash));
            put(md, archivedAt.withOffsetSameInstant(ZoneOffset.UTC)
                    .truncatedTo(ChronoUnit.MICROS).format(UTC_FORMAT));
            put(md, authorizedBy);
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Feed a length-prefixed component: 8-byte big-endian UTF-8 length, then the UTF-8 bytes. */
    private void put(MessageDigest md, String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        md.update(longToBytes(bytes.length));
        md.update(bytes);
    }

    private byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (v & 0xFF);
            v >>= 8;
        }
        return b;
    }
}
