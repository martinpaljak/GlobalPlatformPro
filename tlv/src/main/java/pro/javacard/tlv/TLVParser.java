package pro.javacard.tlv;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

// Stateless TLV parser
public final class TLVParser {
    private TLVParser() {}

    public static List<TLV> parse(ByteBuffer buf, Tag.Type type) {
        var result = new ArrayList<TLV>();
        while (buf.hasRemaining()) {
            result.add(parseOne(buf, type));
        }
        return List.copyOf(result);
    }

    public static List<TLV> parse(byte[] data, Tag.Type type) {
        return parse(ByteBuffer.wrap(data), type);
    }

    public static List<TLV> parse(byte[] data, int offset, int length, Tag.Type type) {
        return parse(ByteBuffer.wrap(data, offset, length), type);
    }

    public static TLV parseOne(ByteBuffer buf, Tag.Type type) {
        try {
            Tag tag = switch (type) {
                case BER -> BERTag.parse(buf);
                case SIMPLE -> SimpleTag.parse(buf);
                case DGI -> DGITag.parse(buf);
            };

            int length = switch (type) {
                case BER -> Len.ber(buf);
                case SIMPLE, DGI -> Len.ext(buf);
            };
            var value = new byte[length];
            buf.get(value);

            // Only BER-TLV has constructed/primitive semantics
            if (tag instanceof BERTag ber && ber.isConstructed()) {
                var kids = new ArrayList<>(parse(ByteBuffer.wrap(value), type));
                return new TLV(tag, null, kids);
            } else {
                return new TLV(tag, value, null);
            }
        } catch (java.nio.BufferUnderflowException e) {
            throw new IllegalArgumentException("Insufficient data to parse TLV", e);
        }
    }
}
