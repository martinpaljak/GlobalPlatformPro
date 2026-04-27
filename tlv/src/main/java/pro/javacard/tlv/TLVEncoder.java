// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.util.ArrayList;

// Stateless TLV encoder
public final class TLVEncoder {
    private TLVEncoder() {}

    public static byte[] encode(final TLV tlv) {
        final var tag = tlv.tag();
        final var tagBytes = tag.bytes();

        final byte[] valueBytes;
        if (tlv.hasChildren()) {
            final var kids = new ArrayList<byte[]>();
            var total = 0;
            for (TLV child : tlv.children()) {
                final var kid = encode(child);
                total += kid.length;
                kids.add(kid);
            }
            valueBytes = new byte[total];
            var offset = 0;
            for (var kid : kids) {
                System.arraycopy(kid, 0, valueBytes, offset, kid.length);
                offset += kid.length;
            }
        } else {
            valueBytes = tlv.value();
        }

        final byte[] lengthBytes = tag instanceof BERTag
                ? Len.ber(valueBytes.length)
                : Len.ext(valueBytes.length);
        final var result = new byte[tagBytes.length + lengthBytes.length + valueBytes.length];
        System.arraycopy(tagBytes, 0, result, 0, tagBytes.length);
        System.arraycopy(lengthBytes, 0, result, tagBytes.length, lengthBytes.length);
        System.arraycopy(valueBytes, 0, result, tagBytes.length + lengthBytes.length, valueBytes.length);
        return result;
    }
}
