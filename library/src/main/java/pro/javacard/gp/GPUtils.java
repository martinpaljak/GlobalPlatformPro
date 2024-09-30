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
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GPUtils {
    private GPUtils() {}
    // Knows both hex and dec
    public static int intValue(String s) {
        if (s.trim().toLowerCase().startsWith("0x")) {
            return Integer.parseInt(s.substring(2), 16);
        }
        return Integer.parseInt(s, 10);
    }

    // Prints both hex and dec
    public static String intString(int i) {
        return String.format("%d (0x%02X)", i, i);
    }

    public static String byteArrayToReadableString(byte[] array) {
        if (array == null) {
            return "(null)";
        }
        StringBuilder s = new StringBuilder();
        for (byte b : array) {
            char c = (char) b;
            s.append(((c >= 0x20) && (c < 0x7f)) ? (c) : ("."));
        }
        return "|" + s.toString() + "|";
    }

    public static byte[] concatenate(byte[]... args) {
        int length = 0, pos = 0;
        for (byte[] arg : args) {
            length += arg.length;
        }
        byte[] result = new byte[length];
        for (byte[] arg : args) {
            System.arraycopy(arg, 0, result, pos, arg.length);
            pos += arg.length;
        }
        return result;
    }

    public static List<byte[]> splitArray(byte[] array, int blockSize) {
        List<byte[]> result = new ArrayList<>();

        int len = array.length;
        int offset = 0;
        int left = len - offset;
        while (left > 0) {
            int currentLen = Math.min(left, blockSize);
            byte[] block = new byte[currentLen];
            System.arraycopy(array, offset, block, 0, currentLen);
            result.add(block);
            left -= currentLen;
            offset += currentLen;
        }
        return result;
    }

    public static byte[] encodeLength(int len) {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
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
        int first = buffer[offset] & 0xFF;
        if (first <= 0x80) {
            return buffer[offset] & 0xFF;
        } else if (first == 0x81) {
            return buffer[offset + 1] & 0xFF;
        } else if (first == 0x82) {
            return (buffer[offset + 1] & 0xFF) << 8 | (buffer[offset + 2] & 0xFF);
        } else
            throw new GPDataException("Invalid length encoding", Arrays.copyOfRange(buffer, offset, offset + 3));
    }

    public static int getLenLen(byte[] buffer, int offset) {
        if ((buffer[offset] & 0xFF) <= 0x80)
            return 1;
        else return (buffer[offset] & 0xFF) - 0x7F;
    }

    // Encodes APDU LC value, which has either length of 1 byte or 3 bytes (for extended length APDUs)
    // If LC or LE is bigger than fits in one byte (255), LC must be encoded in three bytes
    public static byte[] encodeLcLength(int lc, int le) {
        if (lc > 255 || le > 256) {
            byte[] lc_ba = ByteBuffer.allocate(4).putInt(lc).array();
            return Arrays.copyOfRange(lc_ba, 1, 4);
        } else
            return new byte[]{(byte) lc};
    }

    // Assumes the bignum length must be even
    static byte[] positive(byte[] bytes) {
        if (bytes[0] == 0 && bytes.length % 2 == 1) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    // JavaCard requires values without sign byte (assumed positive)
    static byte[] positive(BigInteger i) {
        byte[] bytes = i.toByteArray();
        return positive(bytes);
    }

    static void trace_lv(byte[] data, Logger logger) {
        try {
            for (String s : visualize_lv(data))
                logger.trace(s);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid LV data: {}", Hex.toHexString(data), e);
        }
    }

    static List<String> visualize_lv(byte[] data) {
        List<String> result = new ArrayList<>();
        try {
            for (int i = 0; i < data.length; ) {
                int l = getLength(data, i);
                int lenLen = getLenLen(data, i);
                result.add(String.format("[%s] %s", HexUtils.bin2hex(Arrays.copyOfRange(data, i, i + lenLen)), HexUtils.bin2hex(Arrays.copyOfRange(data, i + lenLen, i + lenLen + l))));
                i += lenLen + l;
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException("Not valid LV structure: " + e.getMessage(), e);
        }
        return result;
    }


    static String spacer(int n) {
        return new String(new char[n]).replace('\0', ' ');
    }


    static void dump(BerTlv tlv, int depth, List<String> result) {
        if (tlv.isConstructed()) {
            result.add(String.format("%s[%s]", spacer(depth * 5), Hex.toHexString(tlv.getTag().bytes)));

            for (BerTlv child : tlv.getValues()) {
                dump(child, depth + 1, result);
            }
        } else {
            result.add(String.format("%s[%s] %s", spacer(depth * 5), Hex.toHexString(tlv.getTag().bytes), Hex.toHexString(tlv.getBytesValue())));
        }
    }

    static void dump(BerTlvs tlv, int depth, List<String> result) {

        for (BerTlv t : tlv.getList()) {
            dump(t, depth, result);
        }
    }

    public static List<String> visualize_tlv(byte[] payload) {
        ArrayList<String> result = new ArrayList<>();
        try {
            BerTlvs tlvs = new BerTlvParser().parse(payload);
            dump(tlvs, 0, result);
        } catch (ArrayIndexOutOfBoundsException | IllegalStateException e) {
            throw new IllegalArgumentException("Not valid TLVs: " + e.getMessage(), e);
        }
        return result;
    }

    static void trace_tlv(byte[] data, Logger l) {
        try {
            for (String s : visualize_tlv(data))
                l.trace(s);
        } catch (IllegalArgumentException e) {
            l.error("Invalid TLV data: {}", Hex.toHexString(data), e);
        }
    }
}
