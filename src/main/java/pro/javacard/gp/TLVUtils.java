package pro.javacard.gp;

import java.util.Arrays;

import apdu4j.HexUtils;

public final class TLVUtils {

	static int getTagLength(byte[] data, int offset) {
		++offset; // FIXME: jumpOverTag
		return getLength(data, offset);
	}


	static byte[] getTLVValueAsBytes(byte[] data, int offset) {
		int len = getTagLength(data, offset);
		return Arrays.copyOfRange(data, offset + 2, offset + 2 + len);
	}


	static int getLength(byte[] data, int offset) {
		return data[offset] & 0x00FF;
	}


	public static final short getShort(byte bArray[], int bOff) {
		return (short) ((bArray[bOff] << 8) + (bArray[bOff + 1] & 0xff));
	}

	// Given a MSB byte array with a length, increment it by one.
	static void buffer_increment(byte[] buffer, int offset, int len) {
		if (len < 1)
			return;
		for (int i = offset + len - 1; i >= offset; i--) {
			if (buffer[i] != (byte) 0xFF) {
				buffer[i]++;
				break;
			} else
				buffer[i] = (byte) 0x00;
		}
	}
}
