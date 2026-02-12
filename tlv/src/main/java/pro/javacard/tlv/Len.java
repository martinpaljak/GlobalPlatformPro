/*
 * Copyright (c) 2025 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package pro.javacard.tlv;

import java.nio.ByteBuffer;

// Length encoding/decoding for TLV structures
public final class Len {
    private Len() {}

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
