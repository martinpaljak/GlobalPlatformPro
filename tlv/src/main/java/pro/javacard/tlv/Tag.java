package pro.javacard.tlv;

import java.util.HexFormat;

// Generic tag interface for different TLV encoding schemes
public interface Tag {
    enum Type { BER, SIMPLE, DGI }

    byte[] bytes();

    default String toHex() {
        return "[" + HexFormat.of().withUpperCase().formatHex(bytes()) + "]";
    }

    static Tag ber(byte... bytes) {
        return new BERTag(bytes);
    }

    static Tag ber(String hex) {
        return new BERTag(HexFormat.of().parseHex(hex.replaceAll("\\s", "")));
    }

    static Tag ber(int b1) {
        return new BERTag(new byte[]{(byte) b1});
    }

    static Tag ber(int b1, int b2) {
        return new BERTag(new byte[]{(byte) b1, (byte) b2});
    }

    static Tag simple(byte b) {
        return new SimpleTag(b);
    }

    static Tag dgi(int dgi) {
        return new DGITag(dgi);
    }
}
