package pro.javacard.tlv;

import java.util.ArrayList;

// Stateless TLV encoder
public final class TLVEncoder {
    private TLVEncoder() {}

    public static byte[] encode(TLV tlv) {
        var tag = tlv.tag();
        var tagBytes = tag.bytes();

        final byte[] valueBytes;
        if (tlv.hasChildren()) {
            var kids = new ArrayList<byte[]>();
            var total = 0;
            for (TLV child : tlv.children()) {
                var kid = encode(child);
                total += kid.length;
                kids.add(kid);
            }
            valueBytes = new byte[total];
            int offset = 0;
            for (var kid : kids) {
                System.arraycopy(kid, 0, valueBytes, offset, kid.length);
                offset += kid.length;
            }
        } else {
            valueBytes = tlv.value();
        }

        byte[] lengthBytes = tag instanceof BERTag
                ? Len.ber(valueBytes.length)
                : Len.ext(valueBytes.length);
        var result = new byte[tagBytes.length + lengthBytes.length + valueBytes.length];
        System.arraycopy(tagBytes, 0, result, 0, tagBytes.length);
        System.arraycopy(lengthBytes, 0, result, tagBytes.length, lengthBytes.length);
        System.arraycopy(valueBytes, 0, result, tagBytes.length + lengthBytes.length, valueBytes.length);
        return result;
    }
}
