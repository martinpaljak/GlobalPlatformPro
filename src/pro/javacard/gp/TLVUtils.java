package pro.javacard.gp;

import java.util.Arrays;

import apdu4j.HexUtils;

public final class TLVUtils {

	static int skipTag(byte[] data, int offset, int tag) {
		if (data[offset] == tag)
			++offset;
		return offset;
	}

	static int skip_tag_or_throw(byte[] data, int offset, int tag) {
		int skip = skipTag(data, offset, tag);
		if (skip == offset)
			throw new RuntimeException("Expected tag " + Integer.toHexString(tag) + " but had " + Integer.toHexString(data[offset]));
		return skip;
	}

	static int get_length(byte[] data, int offset) {
		return data[offset] & 0x00FF;
	}

	static int skipLength(byte[] data, int offset) {
		return offset + 1;
	}

	static int get_byte_value(byte[] data, int offset) {
		return data[offset] & 0x00FF;
	}

	static int expectTag(byte[] data, int offset, byte tag) {
		if (data[offset] == tag)
			++offset;
		return offset;
	}

	static int skipTagAndLength(byte[] data, int offset, byte tag) {
		offset = expectTag(data, offset, tag);
		offset = skipLength(data, offset);
		return offset;
	}

	static int getTagLength(byte[] data, int offset) {
		++offset; // FIXME: jumpOverTag
		return getLength(data, offset);
	}

	static int getTLVTag(byte[] data, int offset) {
		return data[offset] & 0xFF;
	}

	static String getTLVValueAsHex(byte[] data, int offset) {
		int len = getTagLength(data, offset);
		return HexUtils.bin2hex(Arrays.copyOfRange(data, offset + 2, offset + 2 + len));
	}

	static byte[] getTLVValueAsBytes(byte[] data, int offset) {
		int len = getTagLength(data, offset);
		return Arrays.copyOfRange(data, offset + 2, offset + 2 + len);
	}

	static byte[] getTLVAsBytes(byte[] data, int offset) {
		int len = getTagLength(data, offset);
		return Arrays.copyOfRange(data, offset, offset + 2 + len);
	}

	static int getTLVValueOffset(byte[] data, int offset) {
		// FIXME
		return offset + 2;
	}

	static int getTagLength(byte[] data, int offset, byte tag) {
		offset = expectTag(data, offset, tag);
		offset = skipLength(data, offset);
		return offset;
	}

	static int getLength(byte[] data, int offset) {
		return data[offset] & 0x00FF;
	}

	static int skipAnyTag(byte[] data, int offset) {
		++offset; // FIXME
		return offset + getLength(data, offset) + 1;
	}

	static int findTag(byte[] data, int offset, byte tag) {
		while (true) {
			if (data[offset] == tag) {
				return offset;
			} else {
				offset = skipAnyTag(data, offset);
			}
		}
	}

	static int findTag(byte[] data, int offset, short tag) {
		while (true) {
			if (getShort(data, offset) == tag) {
				return offset;
			} else {
				offset = skipAnyTag(data, offset);
			}
		}
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
