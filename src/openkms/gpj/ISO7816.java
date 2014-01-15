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

package openkms.gpj;

/**
 * Constants interface for ISO 7816 (and friends).
 *
 * @author Engelbert Hubbers (hubbers@cs.ru.nl)
 * @author Martijn Oostdijk (martijno@cs.ru.nl)
 * @author Martin Paljak
 */
public interface ISO7816 {

	public static final byte OFFSET_CLA = (byte) 0;

	public static final byte OFFSET_INS = (byte) 1;

	public static final byte OFFSET_P1 = (byte) 2;

	public static final byte OFFSET_P2 = (byte) 3;

	public static final byte OFFSET_LC = (byte) 4;

	public static final byte OFFSET_CDATA = (byte) 5;

	public static final byte CLA_ISO7816 = (byte) 0x00;

	public static final byte INS_ERASE_BINARY_0E = 0x0E;

	public static final byte INS_VERIFY_20 = 0x20;

	public static final byte INS_CHANGE_CHV_24 = 0x24;

	public static final byte INS_UNBLOCK_CHV_2C = 0x2C;

	public static final byte INS_EXTERNAL_AUTHENTICATE_82 = (byte) 0x82;

	public static final byte INS_MUTUAL_AUTHENTICATE_82 = (byte) 0x82;

	public static final byte INS_GET_CHALLENGE_84 = (byte) 0x84;

	public static final byte INS_ASK_RANDOM = (byte) 0x84;

	public static final byte INS_GIVE_RANDOM = (byte) 0x86;

	public static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;

	public static final byte INS_SEEK = (byte) 0xA2;

	public static final byte INS_SELECT = (byte) 0xA4;

	public static final byte INS_SELECT_FILE = (byte) 0xA4;

	public static final byte INS_CLOSE_APPLICATION = (byte) 0xAC;

	public static final byte INS_READ_BINARY = (byte) 0xB0;

	public static final byte INS_READ_BINARY2 = (byte) 0xB1;

	public static final byte INS_READ_RECORD = (byte) 0xB2;

	public static final byte INS_READ_RECORD2 = (byte) 0xB3;

	public static final byte INS_READ_RECORDS = (byte) 0xB2;

	public static final byte INS_GET_RESPONSE = (byte) 0xC0;

	public static final byte INS_ENVELOPE = (byte) 0xC2;

	public static final byte INS_GET_DATA = (byte) 0xCA;

	public static final byte INS_WRITE_BINARY = (byte) 0xD0;

	public static final byte INS_WRITE_RECORD = (byte) 0xD2;

	public static final byte INS_UPDATE_BINARY = (byte) 0xD6;

	public static final byte INS_LOAD_KEY_FILE = (byte) 0xD8;

	public static final byte INS_PUT_DATA = (byte) 0xDA;

	public static final byte INS_UPDATE_RECORD = (byte) 0xDC;

	public static final byte INS_CREATE_FILE = (byte) 0xE0;

	public static final byte INS_APPEND_RECORD = (byte) 0xE2;

	public static final byte INS_DELETE_FILE = (byte) 0xE4;

	///////////////////////////////////////////////////////
	public static final short SW_BYTES_REMAINING_00 = (short) 0x6100;

	public static final short SW_END_OF_FILE = (short) 0x6282;

	public static final short SW_LESS_DATA_RESPONDED_THAN_REQUESTED = (short) 0x6287;

	public static final short SW_WRONG_LENGTH = (short) 0x6700;

	public static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;

	public static final short SW_AUTHENTICATION_METHOD_BLOCKED = (short) 0x6983;

	public static final short SW_DATA_INVALID = (short) 0x6984;

	public static final short SW_CONDITIONS_OF_USE_NOT_SATISFIED = (short) 0x6985;

	public static final short SW_COMMAND_NOT_ALLOWED = (short) 0x6986;

	public static final short SW_EXPECTED_SM_DATA_OBJECTS_MISSING = (short) 0x6987;

	public static final short SW_SM_DATA_OBJECTS_INCORRECT = (short) 0x6988;

	public static final short SW_KEY_USAGE_ERROR = (short) 0x69C1;

	public static final short SW_WRONG_DATA = (short) 0x6A80;

	public static final short SW_FILEHEADER_INCONSISTENT = (short) 0x6A80;

	public static final short SW_FUNC_NOT_SUPPORTED = (short) 0x6A81;

	public static final short SW_FILE_NOT_FOUND = (short) 0x6A82;

	public static final short SW_RECORD_NOT_FOUND = (short) 0x6A83;

	public static final short SW_FILE_FULL = (short) 0x6A84;

	public static final short SW_OUT_OF_MEMORY = (short) 0x6A84;

	public static final short SW_INCORRECT_P1P2 = (short) 0x6A86;

	public static final short SW_KEY_NOT_FOUND = (short) 0x6A88;

	public static final short SW_WRONG_P1P2 = (short) 0x6B00;

	public static final short SW_CORRECT_LENGTH_00 = (short) 0x6C00;

	public static final short SW_INS_NOT_SUPPORTED = (short) 0x6D00;

	public static final short SW_CLA_NOT_SUPPORTED = (short) 0x6E00;

	public static final short SW_NO_PRECISE_DIAGNOSIS = (short) 0x6F00;

	public static final short SW_CARD_TERMINATED = (short) 0x6FFF;

	public static final short SW_NO_ERROR = (short) 0x9000;
}
