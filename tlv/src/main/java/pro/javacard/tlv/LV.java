// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

// Length-value (no tag) sequences. Lengths are emitted as canonical BER via Len
// (128 -> 81 80) but parsed tolerantly: a single byte 0x00..0x80 is the length
// itself, so 0x80 reads as 128 - the GlobalPlatform legacy one-byte shorthand -
// while 0x81/0x82/0x83 introduce a 1-, 2- or 3-byte length. Indefinite-length BER
// does not occur in these structures, so accepting 0x80 as 128 is unambiguous.
public final class LV {

    private static final HexFormat HEX = HexFormat.of().withUpperCase();

    private LV() {
    }

    // Concatenate parts into a length-value sequence: each part is written as its
    // BER-encoded length followed by its bytes; a null part becomes a single 0x00
    // (an empty entry). Values below 128 bytes get a one-byte length; longer ones
    // grow to the two- or three-byte length forms.
    public static byte[] encode(final byte[]... parts) {
        final var bo = new ByteArrayOutputStream();
        for (final var part : parts) {
            final var p = part == null ? new byte[0] : part;
            bo.writeBytes(Len.ber(p.length));
            bo.writeBytes(p);
        }
        return bo.toByteArray();
    }

    // Split a length-value chain back into its individual values.
    public static List<byte[]> parse(final byte[] data) {
        final var result = new ArrayList<byte[]>();
        final var buf = ByteBuffer.wrap(data);
        while (buf.hasRemaining()) {
            final var value = new byte[length(buf, data)];
            buf.get(value);
            result.add(value);
        }
        return result;
    }

    // One "[lengthBytes] value" line per entry, for logging and inspection.
    public static List<String> visualize(final byte[] data) {
        final var result = new ArrayList<String>();
        final var buf = ByteBuffer.wrap(data);
        while (buf.hasRemaining()) {
            final var start = buf.position();
            final var len = length(buf, data);
            final var lenBytes = Arrays.copyOfRange(data, start, buf.position());
            final var value = new byte[len];
            buf.get(value);
            result.add("[%s] %s".formatted(HEX.formatHex(lenBytes), HEX.formatHex(value)));
        }
        return result;
    }

    // One length: a byte 0x00..0x80 is the length itself (0x80 = 128), and
    // 0x81/0x82/0x83 introduce that many following bytes. A length that overruns
    // the remaining data is rejected up front, so a crafted value can not drive an
    // oversized allocation.
    private static int length(final ByteBuffer buf, final byte[] data) {
        var len = buf.get() & 0xFF;
        if (len > 0x80) {
            final var n = len & 0x7F;
            if (n > 3 || buf.remaining() < n) {
                throw malformed(data);
            }
            len = 0;
            for (var i = 0; i < n; i++) {
                len = (len << 8) | (buf.get() & 0xFF);
            }
        }
        if (len > buf.remaining()) {
            throw malformed(data);
        }
        return len;
    }

    private static IllegalArgumentException malformed(final byte[] data) {
        return new IllegalArgumentException("Not a valid length-value structure: " + HEX.formatHex(data));
    }
}
