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
import java.util.ArrayList;
import java.util.List;

// Stateless TLV parser
public final class TLVParser {
    private TLVParser() {}

    public static List<TLV> parse(final ByteBuffer buf, final Tag.Type type) {
        final var result = new ArrayList<TLV>();
        while (buf.hasRemaining()) {
            result.add(parseOne(buf, type));
        }
        return List.copyOf(result);
    }

    public static List<TLV> parse(final byte[] data, final Tag.Type type) {
        return parse(ByteBuffer.wrap(data), type);
    }

    public static List<TLV> parse(final byte[] data, final int offset, final int length, final Tag.Type type) {
        return parse(ByteBuffer.wrap(data, offset, length), type);
    }

    public static TLV parseOne(final ByteBuffer buf, final Tag.Type type) {
        try {
            final var tag = switch (type) {
                case BER -> BERTag.parse(buf);
                case SIMPLE -> SimpleTag.parse(buf);
                case DGI -> DGITag.parse(buf);
            };

            final var length = switch (type) {
                case BER -> Len.ber(buf);
                case SIMPLE, DGI -> Len.ext(buf);
            };
            final var value = new byte[length];
            buf.get(value);

            // Only BER-TLV has constructed/primitive semantics
            if (tag instanceof BERTag ber && ber.isConstructed()) {
                final var kids = new ArrayList<>(parse(ByteBuffer.wrap(value), type));
                return new TLV(tag, null, kids);
            } else {
                return new TLV(tag, value, null);
            }
        } catch (java.nio.BufferUnderflowException e) {
            throw new IllegalArgumentException("Insufficient data to parse TLV", e);
        }
    }
}
