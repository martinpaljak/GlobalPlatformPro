// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

// Stateless TLV parser
public final class TLVParser {
    private TLVParser() {}

    public static List<TLV> parse(final ByteBuffer buf, final Tag.Type type) {
        final var result = new ArrayList<TLV>();
        while (buf.hasRemaining()) {
            result.add(parseOne(buf, type));
        }
        return List.copyOf(result);
    }

    public static List<TLV> parse(final byte[] data, final Tag.Type type) {
        return parse(ByteBuffer.wrap(data), type);
    }

    public static List<TLV> parse(final byte[] data, final int offset, final int length, final Tag.Type type) {
        return parse(ByteBuffer.wrap(data, offset, length), type);
    }

    public static TLV parseOne(final ByteBuffer buf, final Tag.Type type) {
        try {
            final var tag = switch (type) {
                case BER -> BERTag.parse(buf);
                case SIMPLE -> SimpleTag.parse(buf);
                case DGI -> DGITag.parse(buf);
            };

            final var length = switch (type) {
                case BER -> Len.ber(buf);
                case SIMPLE, DGI -> Len.ext(buf);
            };
            final var value = new byte[length];
            buf.get(value);

            // Only BER-TLV has constructed/primitive semantics
            if (tag instanceof BERTag ber && ber.isConstructed()) {
                final var kids = new ArrayList<>(parse(ByteBuffer.wrap(value), type));
                return new TLV(tag, null, kids);
            } else {
                return new TLV(tag, value, null);
            }
        } catch (BufferUnderflowException | IndexOutOfBoundsException | IllegalArgumentException e) {
            throw new TLVParseException("Insufficient data to parse TLV", e);
        }
    }
}
