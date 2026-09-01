// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.nio.ByteBuffer;

// Length encoding/decoding for TLV structures
public final class Len {
    private Len() {}

    // Both directions: ber and ext disagree on the wire
    public interface Codec {
        int decode(ByteBuffer buf);
        byte[] encode(int len);

        Codec BER = new Codec() {           // 81/82/83 long form
            @Override
            public int decode(final ByteBuffer buf) {
                return Len.ber(buf);
            }

            @Override
            public byte[] encode(final int len) {
                return Len.ber(len);
            }
        };
        Codec EXT = new Codec() {           // 0xFF-marker 2-byte form
            @Override
            public int decode(final ByteBuffer buf) {
                return Len.ext(buf);
            }

            @Override
            public byte[] encode(final int len) {
                return Len.ext(len);
            }
        };
    }

    // BER-TLV length (ISO 7816-4)
    public static byte[] ber(int len) {
        if (len < 0) {
            throw new IllegalArgumentException("Negative length");
        }
        if (len < 0x80) {
            return new byte[] { (byte) len };
        } else if (len < 0x100) {
            return new byte[] { (byte) 0x81, (byte) len };
        } else if (len < 0x10000) {
            return new byte[] { (byte) 0x82, (byte) (len >> 8), (byte) len };
        } else if (len < 0x1000000) {
            return new byte[] { (byte) 0x83, (byte) (len >> 16), (byte) (len >> 8), (byte) len };
        }
        throw new IllegalArgumentException("Length too large (max 3 bytes)");
    }

    public static int ber(final ByteBuffer buf) {
        final var b = buf.get() & 0xFF;
        if ((b & 0x80) == 0) {
            return b;
        }
        final var n = b & 0x7F;
        if (n > 3) {
            throw new IllegalArgumentException("Length too large");
        }
        var len = 0;
        for (var i = 0; i < n; i++) {
            len = (len << 8) | (buf.get() & 0xFF);
        }
        return len;
    }

    // Extended length (SimpleTLV / DGI) - 0xFF marker for 2-byte length
    public static byte[] ext(int len) {
        if (len < 0) {
            throw new IllegalArgumentException("Negative length");
        }
        if (len < 0xFF) {
            return new byte[] { (byte) len };
        } else if (len < 0x10000) {
            return new byte[] { (byte) 0xFF, (byte) (len >> 8), (byte) len };
        }
        throw new IllegalArgumentException("Length too large (max 65535)");
    }

    public static int ext(final ByteBuffer buf) {
        final var b = buf.get() & 0xFF;
        if (b != 0xFF) {
            return b;
        }
        return ((buf.get() & 0xFF) << 8) | (buf.get() & 0xFF);
    }
}
