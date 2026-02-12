/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import pro.javacard.tlv.TLV;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
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
        final var bo = new ByteArrayOutputStream();
        // XXX: can probably re-use some existing method somewhere
        if (len < 0x80) {
            bo.write((byte) len);
        } else if (len <= 0xFF) {
            bo.write((byte) 0x81);
            bo.write((byte) len);
        } else if (len <= 0xFFFF) {
            bo.write((byte) 0x82);
            bo.write((byte) ((len & 0xFF00) >> 8));
            bo.write((byte) (len & 0xFF));
        } else {
            bo.write((byte) 0x83);
            bo.write((byte) ((len & 0xFF0000) >> 16));
            bo.write((byte) ((len & 0xFF00) >> 8));
            bo.write((byte) (len & 0xFF));
        }
        return bo.toByteArray();
    }

    public static int getLength(byte[] buffer, int offset) {
        // XXX: Old specs allow 0x80 for encoding 128 bytes...., so maybe check that 81 80 is in fact > 80
        final var first = buffer[offset] & 0xFF;
        if (first <= 0x80) {
            return buffer[offset] & 0xFF;
        } else if (first == 0x81) {
            return buffer[offset + 1] & 0xFF;
        } else if (first == 0x82) {
            return (buffer[offset + 1] & 0xFF) << 8 | (buffer[offset + 2] & 0xFF);
        } else {
            throw new GPDataException("Invalid length encoding", Arrays.copyOfRange(buffer, offset, offset + 3));
        }
    }

    public static int getLenLen(byte[] buffer, int offset) {
        if ((buffer[offset] & 0xFF) <= 0x80) {
            return 1;
        } else {
            return (buffer[offset] & 0xFF) - 0x7F;
        }
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
    static byte[] positive(BigInteger i) {
        final var bytes = i.toByteArray();
        return positive(bytes);
    }

    public static void trace_lv(final byte[] data, final Logger logger) {
        try {
            for (String s : visualize_lv(data)) {
                logger.trace(s);
            }
        } catch (IllegalArgumentException e) {
            logger.error("Invalid LV data: {}", Hex.toHexString(data), e);
        }
    }

    static List<String> visualize_lv(final byte[] data) {
        final var result = new ArrayList<String>();
        try {
            for (var i = 0; i < data.length;) {
                final var l = getLength(data, i);
                final var lenLen = getLenLen(data, i);
                result.add("[%s] %s".formatted(HexUtils.bin2hex(Arrays.copyOfRange(data, i, i + lenLen)),
                        HexUtils.bin2hex(Arrays.copyOfRange(data, i + lenLen, i + lenLen + l))));
                i += lenLen + l;
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException("Not valid LV structure: " + e.getMessage(), e);
        }
        return result;
    }

    static void dump(final TLV tlv, final int depth, final List<String> result) {
        if (tlv.hasChildren()) {
            result.add("%s[%s]".formatted(" ".repeat(depth * 5), Hex.toHexString(tlv.tag().bytes())));

            for (TLV child : tlv.children()) {
                dump(child, depth + 1, result);
            }
        } else {
            result.add("%s[%s] %s".formatted(" ".repeat(depth * 5), Hex.toHexString(tlv.tag().bytes()), Hex.toHexString(tlv.value())));
        }
    }

    static void dump(final List<TLV> list, final int depth, final List<String> result) {
        for (TLV t : list) {
            dump(t, depth, result);
        }
    }

    public static List<String> visualize_tlv(final byte[] payload) {
        final var result = new ArrayList<String>();
        try {
            final var tlvs = TLV.parse(payload);
            dump(tlvs, 0, result);
        } catch (ArrayIndexOutOfBoundsException | IllegalStateException e) {
            throw new IllegalArgumentException("Not valid TLVs: " + e.getMessage(), e);
        }
        return result;
    }

    static void trace_tlv(final byte[] data, final Logger l) {
        try {
            for (String s : visualize_tlv(data)) {
                l.trace(s);
            }
        } catch (IllegalArgumentException e) {
            l.error("Invalid TLV data: {}", Hex.toHexString(data), e);
        }
    }
}
