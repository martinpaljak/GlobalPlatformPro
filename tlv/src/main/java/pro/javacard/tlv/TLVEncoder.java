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

import java.util.ArrayList;

// Stateless TLV encoder
public final class TLVEncoder {
    private TLVEncoder() {
    }

    public static byte[] encode(TLV tlv) {
        var tag = tlv.tag();
        var tagBytes = tag.bytes();

        final byte[] valueBytes;
        if (tlv.hasChildren()) {
            var kids = new ArrayList<byte[]>();
            var total = 0;
            for (TLV child : tlv.children()) {
                var kid = encode(child);
                total += kid.length;
                kids.add(kid);
            }
            valueBytes = new byte[total];
            int offset = 0;
            for (var kid : kids) {
                System.arraycopy(kid, 0, valueBytes, offset, kid.length);
                offset += kid.length;
            }
        } else {
            valueBytes = tlv.value();
        }

        byte[] lengthBytes = tag instanceof BERTag
                ? Len.ber(valueBytes.length)
                : Len.ext(valueBytes.length);
        var result = new byte[tagBytes.length + lengthBytes.length + valueBytes.length];
        System.arraycopy(tagBytes, 0, result, 0, tagBytes.length);
        System.arraycopy(lengthBytes, 0, result, tagBytes.length, lengthBytes.length);
        System.arraycopy(valueBytes, 0, result, tagBytes.length + lengthBytes.length, valueBytes.length);
        return result;
    }
}
