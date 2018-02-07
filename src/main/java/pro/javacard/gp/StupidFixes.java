package pro.javacard.gp;

import apdu4j.HexUtils;

import java.util.Arrays;

// Stupid fixes for bogus/broken cards
public final class StupidFixes {

    public static byte[] fix_get_status(byte[] r) {
        // Some chinese SIM, with an empty privileges byte
        if (Arrays.equals(r, HexUtils.hex2bin("E3124F07A00000015100009F700107C5EA028000")))
            return HexUtils.hex2bin("E3144F07A00000015100009F700107C50180EA028000");
        return r;
    }
}
