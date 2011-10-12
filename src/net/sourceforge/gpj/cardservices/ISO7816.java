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

/**
 * Constants interface for ISO 7816 (and friends).
 * 
 * @author Engelbert Hubbers (hubbers@cs.ru.nl)
 * @author Martijn Oostdijk (martijno@cs.ru.nl)
 * @version $Revision: 206 $
 */
public interface ISO7816 {
    static final byte OFFSET_CLA = (byte) 0;

    static final byte OFFSET_INS = (byte) 1;

    static final byte OFFSET_P1 = (byte) 2;

    static final byte OFFSET_P2 = (byte) 3;

    static final byte OFFSET_LC = (byte) 4;

    static final byte OFFSET_CDATA = (byte) 5;

    static final byte CLA_ISO7816 = (byte) 0x00;

    static final byte INVALIDATE_CHV = 0x04;

    static final byte INS_ERASE_BINARY = 0x0E;

    static final byte INS_VERIFY = 0x20;

    static final byte INS_CHANGE_CHV = 0x24;

    static final byte INS_UNBLOCK_CHV = 0x2C;

    static final byte INS_DECREASE = 0x30;

    static final byte INS_INCREASE = 0x32;

    static final byte INS_DECREASE_STAMPED = 0x34;

    static final byte INS_REHABILITATE_CHV = 0x44;

    static final byte INS_MANAGE_CHANNEL = 0x70;

    static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;

    static final byte INS_MUTUAL_AUTHENTICATE = (byte) 0x82;

    static final byte INS_GET_CHALLENGE = (byte) 0x84;

    static final byte INS_ASK_RANDOM = (byte) 0x84;

    static final byte INS_GIVE_RANDOM = (byte) 0x86;

    static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;

    static final byte INS_SEEK = (byte) 0xA2;

    static final byte INS_SELECT = (byte) 0xA4;

    static final byte INS_SELECT_FILE = (byte) 0xA4;

    static final byte INS_CLOSE_APPLICATION = (byte) 0xAC;

    static final byte INS_READ_BINARY = (byte) 0xB0;

    static final byte INS_READ_BINARY2 = (byte) 0xB1;

    static final byte INS_READ_RECORD = (byte) 0xB2;

    static final byte INS_READ_RECORD2 = (byte) 0xB3;

    static final byte INS_READ_RECORDS = (byte) 0xB2;

    static final byte INS_READ_BINARY_STAMPED = (byte) 0xB4;

    static final byte INS_READ_RECORD_STAMPED = (byte) 0xB6;

    static final byte INS_GET_RESPONSE = (byte) 0xC0;

    static final byte INS_ENVELOPE = (byte) 0xC2;

    static final byte INS_GET_DATA = (byte) 0xCA;

    static final byte INS_WRITE_BINARY = (byte) 0xD0;

    static final byte INS_WRITE_RECORD = (byte) 0xD2;

    static final byte INS_UPDATE_BINARY = (byte) 0xD6;

    static final byte INS_LOAD_KEY_FILE = (byte) 0xD8;

    static final byte INS_PUT_DATA = (byte) 0xDA;

    static final byte INS_UPDATE_RECORD = (byte) 0xDC;

    static final byte INS_CREATE_FILE = (byte) 0xE0;

    static final byte INS_APPEND_RECORD = (byte) 0xE2;

    static final byte INS_DELETE_FILE = (byte) 0xE4;

    static final short SW_BYTES_REMAINING_00 = (short) 0x6100;

    static final short SW_END_OF_FILE = (short) 0x6282;

    static final short SW_LESS_DATA_RESPONDED_THAN_REQUESTED = (short) 0x6287;

    static final short SW_WRONG_LENGTH = (short) 0x6700;

    static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;

    static final short SW_FILE_INVALID = (short) 0x6983;

    static final short SW_DATA_INVALID = (short) 0x6984;

    static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;

    static final short SW_COMMAND_NOT_ALLOWED = (short) 0x6986;

    static final short SW_EXPECTED_SM_DATA_OBJECTS_MISSING = (short) 0x6987;

    static final short SW_SM_DATA_OBJECTS_INCORRECT = (short) 0x6988;

    static final short SW_APPLET_SELECT_FAILED = (short) 0x6999;

    static final short SW_KEY_USAGE_ERROR = (short) 0x69C1;

    static final short SW_WRONG_DATA = (short) 0x6A80;

    static final short SW_FILEHEADER_INCONSISTENT = (short) 0x6A80;

    static final short SW_FUNC_NOT_SUPPORTED = (short) 0x6A81;

    static final short SW_FILE_NOT_FOUND = (short) 0x6A82;

    static final short SW_RECORD_NOT_FOUND = (short) 0x6A83;

    static final short SW_FILE_FULL = (short) 0x6A84;

    static final short SW_OUT_OF_MEMORY = (short) 0x6A84;

    static final short SW_INCORRECT_P1P2 = (short) 0x6A86;

    static final short SW_KEY_NOT_FOUND = (short) 0x6A88;

    static final short SW_WRONG_P1P2 = (short) 0x6B00;

    static final short SW_CORRECT_LENGTH_00 = (short) 0x6C00;

    static final short SW_INS_NOT_SUPPORTED = (short) 0x6D00;

    static final short SW_CLA_NOT_SUPPORTED = (short) 0x6E00;

    static final short SW_UNKNOWN = (short) 0x6F00;

    static final short SW_CARD_TERMINATED = (short) 0x6FFF;

    static final short SW_NO_ERROR = (short) 0x9000;
}
