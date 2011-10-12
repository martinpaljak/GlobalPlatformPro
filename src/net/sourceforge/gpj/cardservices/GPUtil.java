/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package net.sourceforge.gpj.cardservices;

import javax.smartcardio.CardException;
import net.sourceforge.gpj.cardservices.ciphers.ICipher;

public class GPUtil {

    public static boolean debug = true;

    public static void debug(Object o) {
        if (debug) {
            System.out.println("DEBUG: " + o.toString());
        }
    }

    public static String byteArrayToReadableString(byte[] array) {
        if (array == null) {
            return "NULL";
        }
        String s = "";
        for (int i = 0; i < array.length; i++) {
            char c = (char) array[i];
            s += (c >= 0x20 && c < 0x7f) ? (c) : (".");
        }
        return "|" + s + "|";
    }

    public static byte[] readableStringToByteArray(String s) {
        if (!s.startsWith("|") && !s.endsWith("|"))
            return null;
        s = s.substring(1, s.length() - 1);
        return s.getBytes();
    }

    public static String byteArrayToString(byte[] a) {
        String result = "";
        String onebyte = null;
        for (int i = 0; i < a.length; i++) {
            onebyte = Integer.toHexString(a[i]);
            if (onebyte.length() == 1)
                onebyte = "0" + onebyte;
            else
                onebyte = onebyte.substring(onebyte.length() - 2);
            result = result + onebyte.toUpperCase() + " ";
        }
        return result;
    }

    public static byte[] stringToByteArray(String s) {
        java.util.Vector<Integer> v = new java.util.Vector<Integer>();
        String operate = new String(s);
        operate = operate.replaceAll(" ", "");
        operate = operate.replaceAll("\t", "");
        operate = operate.replaceAll("\n", "");
        if (operate.endsWith(";"))
            operate = operate.substring(0, operate.length() - 1);
        if (operate.length() % 2 != 0)
            return null;
        int num = 0;
        while (operate.length() > 0) {
            try {
                num = Integer.parseInt(operate.substring(0, 2), 16);
            } catch (NumberFormatException nfe) {
                return null;
            }
            v.add(new Integer(num));
            operate = operate.substring(2);
        }
        byte[] result = new byte[v.size()];
        java.util.Iterator<Integer> it = v.iterator();
        int i = 0;
        while (it.hasNext())
            result[i++] = it.next().byteValue();
        return result;
    }

    public static String swToString(int sw1, int sw2) {
        String result = "";
        String onebyte = null;
        onebyte = Integer.toHexString(sw1);
        if (onebyte.length() == 1)
            onebyte = "0" + onebyte;
        else
            onebyte = onebyte.substring(onebyte.length() - 2);

        result = result + onebyte.toUpperCase() + " ";
        onebyte = Integer.toHexString(sw2);
        if (onebyte.length() == 1)
            onebyte = "0" + onebyte;
        else
            onebyte = onebyte.substring(onebyte.length() - 2);

        result = result + onebyte.toUpperCase() + " ";
        return result;
    }

    public static String swToString(int sw) {
        int sw1 = (sw & 0x0000FF00) >> 8;
        int sw2 = (sw & 0x000000FF);
        return swToString(sw1, sw2);
    }

    public static byte[] pad80(byte[] text, int offset, int length) {
        if (length == -1)
            length = text.length - offset;
        int totalLength = length;
        for (totalLength++; totalLength % 8 != 0; totalLength++)
            ;
        int padlength = totalLength - length;
        byte[] result = new byte[totalLength];
        System.arraycopy(text, offset, result, 0, length);
        result[length] = (byte) 0x80;
        for (int i = 1; i < padlength; i++)
            result[length + i] = (byte) 0x00;
        return result;
    }

    public static byte[] pad80(byte[] text) {
        return pad80(text, 0, text.length);
    }

    public static byte[] mac_3des(byte[] key, byte[] text, byte[] cv)
            throws CardException {
        return mac_3des(key, text, 0, text.length, cv);
    }

    public static byte[] mac_3des(byte[] key, byte[] text, int offset, int length,
            byte[] cv) throws CardException {
        if (length == -1)
            length = text.length - offset;

        try {
            ICipher cipher = ICipher.Factory.getImplementation(
                    ICipher.DESEDE_CBC_NOPADDING, getKey(key, 24), cv);
            byte[] result = new byte[8];
            byte[] res = cipher.encrypt(text, offset, length);
            System.arraycopy(res, res.length - 8, result, 0, 8);
            return result;
        } catch (Exception e) {
            throw new CardException("MAC computation failed.");
        }
    }

    public static byte[] mac_des_3des(byte[] key, byte[] text, byte[] cv)
            throws CardException {
        return mac_des_3des(key, text, 0, text.length, cv);
    }

    public static byte[] mac_des_3des(byte[] key, byte[] text, int offset, int length,
            byte[] cv) throws CardException {
        if (length == -1)
            length = text.length - offset;

        try {
            ICipher cipher1 = ICipher.Factory.getImplementation(
                    ICipher.DES_CBC_NOPADDING, getKey(key, 8), cv);
            ICipher cipher2 = ICipher.Factory.getImplementation(
                    ICipher.DESEDE_CBC_NOPADDING, getKey(key, 24), cv);

            byte[] result = new byte[8];
            byte[] temp;

            if (length > 8) {
                temp = cipher1.encrypt(text, offset, length - 8);
                System.arraycopy(temp, temp.length - 8, result, 0, 8);
                cipher2.setIV(result);
            }
            temp = cipher2.encrypt(text, offset + length - 8, 8);
            System.arraycopy(temp, temp.length - 8, result, 0, 8);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            throw new CardException("MAC computation failed.");
        }
    }

    public static byte[] getKey(byte[] key, int length) {
        if (length == 24) {
            byte[] key24 = new byte[24];
            System.arraycopy(key, 0, key24, 0, 16);
            System.arraycopy(key, 0, key24, 16, 8);
            return key24;
        } else {
            byte[] key8 = new byte[8];
            System.arraycopy(key, 0, key8, 0, 8);
            return key8;
        }
    }

}
