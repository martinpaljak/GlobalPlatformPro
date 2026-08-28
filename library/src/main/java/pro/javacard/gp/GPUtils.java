// SPDX-FileCopyrightText: 2012 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2009 Wojciech Mostowski <woj@cs.ru.nl>
// SPDX-FileCopyrightText: 2009 Francois Kooman <F.Kooman@student.science.ru.nl>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import pro.javacard.tlv.LV;
import pro.javacard.tlv.Len;
import pro.javacard.tlv.TLVs;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public final class GPUtils {
    private GPUtils() {}

    // Knows both hex and dec
    public static int intValue(final String s) {
        if (s.trim().toLowerCase(Locale.ROOT).startsWith("0x")) {
            return Integer.parseInt(s.substring(2), 16);
        }
        return Integer.parseInt(s, 10);
    }

    // Prints both hex and dec
    public static String intString(int i) {
        return "%d (0x%02X)".formatted(i, i);
    }

    public static String bin2readable(final byte[] bytes) {
        if (bytes == null) {
            return "(null)";
        }
        final var s = new StringBuilder();
        for (byte b : bytes) {
            final var c = (char) b;
            s.append(c >= 0x20 && c < 0x7f ? c : '.');
        }
        return "|" + s + "|";
    }

    // Identifiers can be ASCII names or opaque bytes.
    public static String bin2printable(final byte[] bytes) {
        final var s = new String(bytes, StandardCharsets.US_ASCII);
        return bytes.length > 0 && s.chars().allMatch(c -> c >= 0x20 && c < 0x7F) ? s : HexUtils.bin2hex(bytes);
    }

    public static byte[] concatenate(final byte[]... args) {
        var length = 0;
        var pos = 0;
        for (byte[] arg : args) {
            length += arg.length;
        }
        final byte[] result = new byte[length];
        for (byte[] arg : args) {
            System.arraycopy(arg, 0, result, pos, arg.length);
            pos += arg.length;
        }
        return result;
    }

    public static List<byte[]> splitArray(final byte[] array, final int blockSize) {
        final var result = new ArrayList<byte[]>();

        final var len = array.length;
        var offset = 0;
        var left = len - offset;
        while (left > 0) {
            final var currentLen = Math.min(left, blockSize);
            final byte[] block = new byte[currentLen];
            System.arraycopy(array, offset, block, 0, currentLen);
            result.add(block);
            left -= currentLen;
            offset += currentLen;
        }
        return result;
    }

    public static byte[] encodeLength(final int len) {
        return Len.ber(len);
    }

    // Encodes APDU LC value, which has either length of 1 byte or 3 bytes (for extended length APDUs)
    // If LC or LE is bigger than fits in one byte (255), LC must be encoded in three bytes
    public static byte[] encodeLcLength(final int lc, final int le) {
        if (lc > 255 || le > 256) {
            final var lc_ba = ByteBuffer.allocate(4).putInt(lc).array();
            return Arrays.copyOfRange(lc_ba, 1, 4);
        } else {
            return new byte[] { (byte) lc };
        }
    }

    // Assumes the bignum length must be even
    static byte[] positive(final byte[] bytes) {
        if (bytes[0] == 0 && bytes.length % 2 == 1) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    // JavaCard requires values without sign byte (assumed positive)
    public static byte[] positive(BigInteger i) {
        final var bytes = i.toByteArray();
        return positive(bytes);
    }

    public static void trace_lv(final byte[] data, final Logger logger) {
        try {
            for (String s : LV.visualize(data)) {
                logger.trace(s);
            }
        } catch (IllegalArgumentException e) {
            logger.error("Invalid LV data: {}", Hex.toHexString(data), e);
        }
    }

    public static List<String> visualize_tlv(final byte[] payload) {
        return TLVs.visualize(payload);
    }

    static void trace_tlv(final byte[] data, final Logger l) {
        try {
            visualize_tlv(data).forEach(l::trace);
        } catch (RuntimeException e) {
            l.error("Invalid TLV data: {}", Hex.toHexString(data), e);
        }
    }
}
