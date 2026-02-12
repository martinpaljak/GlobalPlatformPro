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
import java.util.Arrays;
import java.util.Objects;

// BER-TLV tag (ISO 7816-4)
@SuppressWarnings("ArrayRecordComponent") // Defensive copies in constructor and accessor
public record BERTag(byte[] bytes) implements Tag {

    public BERTag { bytes = validate(bytes).clone(); }

    @Override
    public byte[] bytes() {
        return bytes.clone();
    }

    static byte[] validate(final byte[] value) {
        Objects.requireNonNull(value, "tag cannot be null");

        if (value.length == 0 || value.length > 4) {
            throw new IllegalArgumentException("Invalid tag length: " + value.length);
        }

        // Multi-byte tags: first byte must have all lower 5 bits set (0x1F)
        if (value.length > 1 && (value[0] & 0x1F) != 0x1F) {
            throw new IllegalArgumentException("Multi-byte tag must have first byte with 0x1F");
        }

        // Middle bytes must have continuation bit (0x80) set
        for (var i = 1; i < value.length - 1; i++) {
            if ((value[i] & 0x80) == 0) {
                throw new IllegalArgumentException("Tag continuation byte missing 0x80 bit");
            }
        }

        // Last byte must NOT have continuation bit
        if (value.length > 1 && (value[value.length - 1] & 0x80) != 0) {
            throw new IllegalArgumentException("Tag last byte should not have 0x80 bit");
        }
        return value;
    }

    public boolean isConstructed() {
        return (bytes[0] & 0x20) == 0x20;
    }

    // Parse from buffer, only move position if successful
    static BERTag parse(final ByteBuffer buffer) {
        final var bytes = new byte[4];
        final var pos = buffer.position();
        var len = 0;

        var b = buffer.get(pos);
        bytes[len++] = b;

        if ((b & 0x1F) == 0x1F) {
            for (var i = 1; i < 4; i++) {
                b = buffer.get(pos + i);
                bytes[len++] = b;
                if ((b & 0x80) == 0) {
                    break;
                }
            }
        }
        // Throws IllegalArgumentException if not valid
        final var tag = new BERTag(Arrays.copyOf(bytes, len));

        // Advance position on success only.
        buffer.position(pos + len);
        return tag;
    }

    @Override
    public String toString() {
        return toHex();
    }

    @Override
    public boolean equals(final Object obj) {
        return obj instanceof BERTag other && Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
