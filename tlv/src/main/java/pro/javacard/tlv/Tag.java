// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.nio.ByteBuffer;
import java.util.HexFormat;

// Generic tag interface for different TLV encoding schemes
public interface Tag {
    HexFormat HEX_FORMAT = HexFormat.of().withUpperCase();

    // Reads one tag off the buffer; encoding is universal via Tag.bytes()
    interface Codec {
        Tag decode(ByteBuffer buf);

        Codec BER = BERTag::parse; // multi-byte, class/constructed bits
        Codec SINGLE_BYTE = SimpleTag::parse; // opaque 0x01..0xFE, no constructed semantics
        Codec DGI = DGITag::parse; // 2-byte big-endian
    }

    byte[] bytes();

    default String toHex() {
        return "[" + HEX_FORMAT.formatHex(bytes()) + "]";
    }

    static Tag ber(byte... bytes) {
        return new BERTag(bytes);
    }

    static Tag ber(String hex) {
        return new BERTag(HexFormat.of().parseHex(hex.replaceAll("\\s", "")));
    }

    static Tag ber(int v) {
        if (v < 0 || v > 0xFFFFFF) {
            throw new IllegalArgumentException("Tag value out of range: " + v);
        }
        if (v <= 0xFF) {
            return new BERTag(new byte[] { (byte) v });
        }
        if (v <= 0xFFFF) {
            return new BERTag(new byte[] { (byte) (v >> 8), (byte) v });
        }
        return new BERTag(new byte[] { (byte) (v >> 16), (byte) (v >> 8), (byte) v });
    }

    static Tag ber(int b1, int b2) {
        if (b1 < 0 || b1 > 0xFF || b2 < 0 || b2 > 0xFF) {
            throw new IllegalArgumentException("Tag bytes out of range: " + Integer.toHexString(b1) + " " + Integer.toHexString(b2));
        }
        return new BERTag(new byte[] { (byte) b1, (byte) b2 });
    }

    static Tag simple(int b) {
        if (b < 0x01 || b > 0xFE) {
            throw new IllegalArgumentException("SimpleTLV tag must be 0x01..0xFE, got " + Integer.toHexString(b));
        }
        return new SimpleTag((byte) b);
    }

    static Tag dgi(int dgi) {
        return new DGITag(dgi);
    }
}
