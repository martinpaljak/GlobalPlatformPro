// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

// Stateless TLV encoder
public final class TLVEncoder {
    private TLVEncoder() {
    }

    public static byte[] encode(final TLV tlv) {
        final var tag = tlv.tag();
        final var tagBytes = tag.bytes();

        final byte[] valueBytes = tlv.hasChildren() ? TLV.encode(tlv.children()) : tlv.value();

        final byte[] lengthBytes = tag instanceof BERTag ? Len.ber(valueBytes.length) : Len.ext(valueBytes.length);
        final var result = new byte[tagBytes.length + lengthBytes.length + valueBytes.length];
        System.arraycopy(tagBytes, 0, result, 0, tagBytes.length);
        System.arraycopy(lengthBytes, 0, result, tagBytes.length, lengthBytes.length);
        System.arraycopy(valueBytes, 0, result, tagBytes.length + lengthBytes.length, valueBytes.length);
        return result;
    }
}
