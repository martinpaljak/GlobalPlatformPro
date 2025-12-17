package pro.javacard.tlv;

import java.nio.ByteBuffer;

// DGI tag (Global Platform) - 2 bytes
public record DGITag(int dgi) implements Tag {

    public DGITag {
        if (dgi < 0 || dgi > 0xFFFF) {
            throw new IllegalArgumentException("DGI must be 0x0000-0xFFFF");
        }
    }

    @Override
    public byte[] bytes() {
        return new byte[]{(byte) (dgi >> 8), (byte) dgi};
    }

    static DGITag parse(ByteBuffer buffer) {
        int high = buffer.get() & 0xFF;
        int low = buffer.get() & 0xFF;
        return new DGITag((high << 8) | low);
    }

    @Override
    public String toString() {
        return toHex();
    }
}
