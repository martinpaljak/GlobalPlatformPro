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

// DGI tag (Global Platform) - 2 bytes
public record DGITag(int dgi) implements Tag {

    public DGITag {
        if (dgi < 0 || dgi > 0xFFFF) {
            throw new IllegalArgumentException("DGI must be 0x0000-0xFFFF");
        }
    }

    @Override
    public byte[] bytes() {
        return new byte[] { (byte) (dgi >> 8), (byte) dgi };
    }

    static DGITag parse(final ByteBuffer buffer) {
        final var high = buffer.get() & 0xFF;
        final var low = buffer.get() & 0xFF;
        return new DGITag((high << 8) | low);
    }

    @Override
    public String toString() {
        return toHex();
    }
}
