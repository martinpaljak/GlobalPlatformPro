// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

// Stateless TLV encoder
public final class TLVEncoder {
    private TLVEncoder() {
    }

    public static byte[] encode(final TLV tlv) {
        final var tag = tlv.tag();
        final byte[] valueBytes = tlv.hasChildren() ? TLV.encode(tlv.children()) : tlv.value();
        // Length form follows the tag type here; the composable TLVParser carries it explicitly instead
        final byte[] lengthBytes = tag instanceof BERTag ? Len.ber(valueBytes.length) : Len.ext(valueBytes.length);
        return concatenate(tag.bytes(), lengthBytes, valueBytes);
    }

    // Join a fixed set of byte fragments in order (tlv cannot reach library's GPUtils.concatenate)
    static byte[] concatenate(final byte[]... parts) {
        var total = 0;
        for (final var p : parts) {
            total += p.length;
        }
        final var result = new byte[total];
        var offset = 0;
        for (final var p : parts) {
            System.arraycopy(p, 0, result, offset, p.length);
            offset += p.length;
        }
        return result;
    }
}
