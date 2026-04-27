// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.util.HexFormat;

// Generic tag interface for different TLV encoding schemes
public interface Tag {
    HexFormat HEX_FORMAT = HexFormat.of().withUpperCase();

    enum Type {
        BER, SIMPLE, DGI
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
            return new BERTag(new byte[]{(byte) v});
        }
        if (v <= 0xFFFF) {
            return new BERTag(new byte[]{(byte) (v >> 8), (byte) v});
        }
        return new BERTag(new byte[]{(byte) (v >> 16), (byte) (v >> 8), (byte) v});
    }

    static Tag ber(int b1, int b2) {
        return new BERTag(new byte[]{(byte) b1, (byte) b2});
    }

    static Tag simple(byte b) {
        return new SimpleTag(b);
    }

    static Tag dgi(int dgi) {
        return new DGITag(dgi);
    }
}
