/*
 * Copyright (c) 2016-2018 Martin Paljak
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
package pro.javacard;

public class HexUtils {
    // This code has been taken from Apache commons-codec 1.7 (License: Apache 2.0)
    private static final char[] UPPER_HEX = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    public static String encodeHexString_imp(final byte[] data) {

        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = UPPER_HEX[(0xF0 & data[i]) >>> 4];
            out[j++] = UPPER_HEX[0x0F & data[i]];
        }
        return new String(out);
    }

    public static byte[] decodeHexString_imp(String str) {
        char data[] = str.toCharArray();
        final int len = data.length;
        if ((len & 0x01) != 0) {
            throw new IllegalArgumentException("Odd number of characters: " + str);
        }
        final byte[] out = new byte[len >> 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            int f = Character.digit(data[j], 16) << 4;
            if (f < 0) {
                throw new IllegalArgumentException("Illegal hex: " + data[j]);
            }
            j++;
            f = f | Character.digit(data[j], 16);
            if (f < 0) {
                throw new IllegalArgumentException("Illegal hex: " + data[j]);
            }
            j++;
            out[i] = (byte) (f & 0xFF);
        }
        return out;
    }

    // End of copied code from commons-codec
    public static byte[] hex2bin(final String hex) {
        return decodeHexString_imp(hex);
    }

    public static String bin2hex(final byte[] bin) {
        return encodeHexString_imp(bin);
    }

    public static byte[] stringToBin(String s) {
        s = s.toUpperCase().replaceAll(" ", "").replaceAll(":", "");
        s = s.replaceAll("0X", "").replaceAll("\n", "").replaceAll("\t", "");
        s = s.replaceAll(";", "");
        return decodeHexString_imp(s);
    }
}
