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

import java.util.HexFormat;

// Generic tag interface for different TLV encoding schemes
public interface Tag {
    enum Type {
        BER, SIMPLE, DGI
    }

    byte[] bytes();

    default String toHex() {
        return "[" + HexFormat.of().withUpperCase().formatHex(bytes()) + "]";
    }

    static Tag ber(byte... bytes) {
        return new BERTag(bytes);
    }

    static Tag ber(String hex) {
        return new BERTag(HexFormat.of().parseHex(hex.replaceAll("\\s", "")));
    }

    static Tag ber(int b1) {
        return new BERTag(new byte[] { (byte) b1 });
    }

    static Tag ber(int b1, int b2) {
        return new BERTag(new byte[] { (byte) b1, (byte) b2 });
    }

    static Tag simple(byte b) {
        return new SimpleTag(b);
    }

    static Tag dgi(int dgi) {
        return new DGITag(dgi);
    }
}
