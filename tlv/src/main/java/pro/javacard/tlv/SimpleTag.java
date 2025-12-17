package pro.javacard.tlv;

import java.nio.ByteBuffer;

// Simple TLV tag (ISO 7816-4) - single byte, values 0x01..0xFE
public record SimpleTag(byte b) implements Tag {

    public SimpleTag {
        int v = b & 0xFF;
        if (v == 0x00 || v == 0xFF) {
            throw new IllegalArgumentException("SimpleTLV tag must be 0x01..0xFE");
        }
    }

    @Override
    public byte[] bytes() {
        return new byte[]{b};
    }

    static SimpleTag parse(ByteBuffer buffer) {
        return new SimpleTag(buffer.get());
    }

    @Override
    public String toString() {
        return toHex();
    }
}
