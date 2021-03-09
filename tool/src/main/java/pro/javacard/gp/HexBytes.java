package pro.javacard.gp;

import apdu4j.HexUtils;

// Small utility class to convert CLI options to byte arrays and have nice help message
public class HexBytes {
    private final byte[] value;

    public HexBytes(String v) {
        value = HexUtils.stringToBin(v);
    }

    public byte[] getValue() {
        return value;
    }
}
