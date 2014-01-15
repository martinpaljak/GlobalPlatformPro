package openkms.gpj;

import java.util.Arrays;


public final  class TLVUtils {

	static short skipTag(byte [] data, short offset, byte tag) {
		if (data[offset] == tag)
			++offset;
		return offset;
	}

	static short skip_tag_or_throw(byte [] data, short offset, byte tag) {
		short skip = skipTag(data, offset, tag);
		if (skip == offset)
			throw new RuntimeException("Expected tag " + Integer.toHexString(tag) + " but had " + Integer.toHexString(data[offset]));
		return skip;
	}

	static short get_length(byte[] data, short offset) {
		return (short) (data[offset] & 0x00FF);
	}

	static short skipLength(byte[] data, short offset) {
		return ++offset;
	}

	static int get_byte_value(byte[] data, short offset) {
		return (short)(data[offset] & 0x00FF);
	}

	static short expectTag(byte[] data, short offset, byte tag) {
		if (data[offset] == tag)
			++offset;
		return offset;
	}
	static short skipTagAndLength(byte []data, short offset, byte tag) {
		offset = expectTag(data, offset, tag);
		offset = skipLength(data, offset);
		return offset;
	}
	
	static short getTagLength(byte [] data, short offset) {
		++offset; // FIXME: jumpOverTag
		return getLength(data, offset);
	}
	
	static int getTLVTag(byte [] data, short offset) {
		return data[offset] & 0xFF;
	}
	
	static String getTLVValueAsHex(byte [] data, short offset) {
		short len = getTagLength(data, offset);
		return LoggingCardTerminal.encodeHexString(Arrays.copyOfRange(data, offset + 2, offset + 2 + len));
	}
	
	static byte[] getTLVValueAsBytes(byte [] data, short offset) {
		short len = getTagLength(data, offset);
		return Arrays.copyOfRange(data, offset + 2, offset + 2 + len);
	}

	static byte[] getTLVAsBytes(byte [] data, short offset) {
		short len = getTagLength(data, offset);
		return Arrays.copyOfRange(data, offset, offset + 2 + len);
	}

	
	static int getTLVValueOffset(byte [] data, short offset) {
		// FIXME
		return offset+2;
	}
	static short getTagLength(byte [] data, short offset, byte tag) {
		offset = expectTag(data, offset, tag);		
		offset = skipLength(data, offset);
		return offset;
	}
	
	static short getLength(byte [] data, short offset) {
		return (short)(data[offset] & 0x00FF);
	}

	static short skipAnyTag(byte [] data, short offset) {
		++offset; // FIXME
		return (short) (offset + getLength(data, offset) +1 );
	}
	
	static short findTag(byte [] data, short offset, byte tag) {
		while (true) {
			if (data[offset] == tag) {
				return offset;
			} else {
				offset = skipAnyTag(data, offset);
			}
		}	 
	}
}
