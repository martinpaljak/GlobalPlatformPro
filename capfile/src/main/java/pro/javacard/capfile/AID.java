/*
 * Copyright (c) 2018 Martin Paljak
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

package pro.javacard.capfile;

import pro.javacard.HexUtils;

import java.util.Arrays;

public final class AID {
    private final byte[] bytes;

    public AID(byte[] bytes) throws IllegalArgumentException {
        this(bytes, 0, bytes.length);
    }

    public AID(String str) throws IllegalArgumentException {
        this(HexUtils.hex2bin(str));
    }

    public AID(byte[] bytes, int offset, int length) throws IllegalArgumentException {
        if ((length < 5) || (length > 16)) {
            throw new IllegalArgumentException("AID must be between 5 and 16 bytes: " + length);
        }
        this.bytes = Arrays.copyOfRange(bytes, offset, offset + length);
    }

    public static AID fromString(Object s) {
        if (s instanceof String) {
            return new AID(HexUtils.stringToBin((String) s));
        }
        throw new IllegalArgumentException("AID should be string");
    }

    public byte[] getBytes() {
        return bytes.clone();
    }

    public int getLength() {
        return bytes.length;
    }

    @Override
    public String toString() {
        return HexUtils.bin2hex(bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof AID) {
            return Arrays.equals(((AID) o).bytes, bytes);
        }
        return false;
    }
}
