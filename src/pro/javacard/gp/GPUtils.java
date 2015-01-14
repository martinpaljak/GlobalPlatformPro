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

package pro.javacard.gp;


public class GPUtils {

	public static String byteArrayToReadableString(byte[] array) {
		if (array == null) {
			return "(null)";
		}
		StringBuffer s = new StringBuffer();
		for (int i = 0; i < array.length; i++) {
			char c = (char) array[i];
			s.append(((c >= 0x20) && (c < 0x7f)) ? (c) : ("."));
		}
		return "|" + s.toString() + "|";
	}

	public static String swToString(int sw) {
		return String.format("%04X", sw);
	}
	public static byte[] concatenate(byte[] a, byte[] b) {
		byte[] s = new byte[a.length + b.length];
		System.arraycopy(a, 0, s, 0, a.length);
		System.arraycopy(b, 0, s, a.length, b.length);
		return s;
	}

}
