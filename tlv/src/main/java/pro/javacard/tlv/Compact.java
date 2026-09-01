// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.io.ByteArrayOutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;

// COMPACT-TLV (ISO/IEC 7816-4, ATR historical bytes). One byte with the tag number in the high nibble
// and the value length in the low nibble, mapped to the primitive BER tag '4X' in memory.
public final class Compact {
    private Compact() {}

    // Serialize BER TLVs to compact form; each tag must be a single-byte '4X' with at most 15 bytes of value.
    public static byte[] encode(final Collection<TLV> tlvs) {
        final var out = new ByteArrayOutputStream();
        for (var tlv : tlvs) {
            final var tag = tlv.tag();
            if (!(tag instanceof BERTag)) {
                throw new IllegalArgumentException("COMPACT-TLV requires a BER tag: " + tag);
            }
            final var tb = tag.bytes();
            if (tb.length != 1 || (tb[0] & 0xF0) != 0x40) {
                throw new IllegalArgumentException("COMPACT-TLV tag must be '4X': " + tag);
            }
            final var value = tlv.value();
            if (value.length > 0x0F) {
                throw new IllegalArgumentException("COMPACT-TLV value exceeds 15 bytes: " + value.length);
            }
            out.write((tb[0] & 0x0F) << 4 | value.length);
            out.write(value, 0, value.length);
        }
        return out.toByteArray();
    }

    // Expand compact form to canonical BER TLVs: tag nibble becomes the '4X' tag, length nibble the value length.
    public static TLVs parse(final byte[] data) {
        final var buf = ByteBuffer.wrap(data);
        final var out = new ArrayList<TLV>();
        try {
            while (buf.hasRemaining()) {
                final var b = buf.get() & 0xFF;
                final var value = new byte[b & 0x0F];
                buf.get(value);
                out.add(TLV.of(Tag.ber(0x40 | (b >> 4)), value));
            }
        } catch (BufferUnderflowException e) {
            throw new TLVParseException("Insufficient data to parse COMPACT-TLV", e);
        }
        return TLVs.of(out);
    }
}
