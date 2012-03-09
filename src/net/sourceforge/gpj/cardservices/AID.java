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

import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;

public class AID {

	public static final String GEMALTO = "GemaltoXpressPro"; 
	
	public static Map<String,AID> SD_AIDS = new TreeMap<String, AID>();

	static {
		SD_AIDS.put("OP201a", new AID(new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 }));
		SD_AIDS.put("OP201b", new AID(new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00 }));
		SD_AIDS.put("GP211", new AID(new byte[] { (byte) 0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00 }));
		SD_AIDS.put(GEMALTO, new AID(new byte[]{(byte) 0xa0, 0x00, 0x00, 0x00, 0x18,0x43, 0x4D, 0x00}));		
	}
	
    private byte[] aidBytes = null;

    /**
     * Construct an application identifier from a complete byte array.
     * 
     * @param bytes
     *            complete application identifier
     * @throws IllegalArgumentException
     *             if the length is outside the permitted range (5-16)
     * 
     */
    public AID(byte[] bytes) {
        this(bytes, 0, bytes.length);
    }

    /**
     * Construct an application identifier from a part of a byte array.
     * 
     * @param bytes
     * @param offset
     *            start index of the application identifier
     * @param length
     *            length
     * @throws IllegalArgumentException
     *             if the length is outside the permitted range (5-16)
     * 
     */
    public AID(byte[] bytes, int offset, int length) {
        this(bytes, offset, length, true);
    }

    /**
     * Construct an application identifier from a complete byte array, possibly
     * ignoring length checking.
     * 
     * @param bytes
     * @param offset
     *            start index of the application identifier
     * @param length
     *            length
     * @param checkLength
     *            perform length check if true (and throw an
     *            IllegalArgumentException if the length is outside the
     *            permitted range)
     * @throws IllegalArgumentException
     *             if the length is outside the permitted range (5-16); if
     *             checkLength is false no check is performed and no exception
     *             thrown
     * 
     */
    public AID(byte[] bytes, int offset, int length, boolean checkLength)
            throws IllegalArgumentException {
        if (checkLength && (length < 5 || length > 16))
            throw new IllegalArgumentException(
                    "AID's are between 5 and 16 bytes");
        aidBytes = new byte[length];
        System.arraycopy(bytes, offset, aidBytes, 0, length);
    }

    public byte[] getBytes() {
        return aidBytes;
    }

    public int getLength() {
        return aidBytes.length;
    }

    public String toString() {
        return GPUtil.byteArrayToString(aidBytes);
    }

    public boolean equals(Object o) {
        if (o instanceof AID) {
            return Arrays.equals(((AID) o).aidBytes, aidBytes);
        }
        return false;
    }
}
