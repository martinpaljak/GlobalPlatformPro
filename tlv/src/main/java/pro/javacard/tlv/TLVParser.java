// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.io.ByteArrayOutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;

// Composable TLV codec: a tag codec, a length codec and whether to recurse into constructed tags.
// GlobalPlatform dialects mix these freely (e.g. opaque 1-byte tag + BER long-form length, never
// constructed - the GPC 2.3.1 11.8.2.3.1 PUT KEY key components).
public final class TLVParser {
    private final Tag.Codec tagCodec;
    private final Len.Codec lenCodec;
    private final boolean constructed;

    private TLVParser(final Tag.Codec tagCodec, final Len.Codec lenCodec, final boolean constructed) {
        this.tagCodec = tagCodec;
        this.lenCodec = lenCodec;
        this.constructed = constructed;
    }

    public static TLVParser of(final Tag.Codec tag, final Len.Codec length, final boolean constructed) {
        return new TLVParser(tag, length, constructed);
    }

    public TLVs parse(final byte[] data) {
        return parse(ByteBuffer.wrap(data));
    }

    public TLVs parse(final ByteBuffer buf) {
        final var result = new ArrayList<TLV>();
        while (buf.hasRemaining()) {
            result.add(parseOne(buf));
        }
        return TLVs.of(result);
    }

    public TLV parseOne(final ByteBuffer buf) {
        try {
            final var tag = tagCodec.decode(buf);
            final var length = lenCodec.decode(buf);
            final var value = new byte[length];
            buf.get(value);

            // Only BER tags carry constructed/primitive semantics; the flag gates that recursion
            if (constructed && tag instanceof BERTag ber && ber.isConstructed()) {
                final var kids = new ArrayList<>(parse(ByteBuffer.wrap(value)));
                return new TLV(tag, null, kids);
            } else {
                return new TLV(tag, value, null);
            }
        } catch (BufferUnderflowException | IndexOutOfBoundsException | IllegalArgumentException e) {
            throw new TLVParseException("Insufficient data to parse TLV", e);
        }
    }

    // Encodes with this codec's length form - the only way to pair an opaque tag with BER length
    public byte[] encode(final TLV tlv) {
        final byte[] valueBytes = tlv.hasChildren() ? encode(tlv.children()) : tlv.value();
        return TLVEncoder.concatenate(tlv.tag().bytes(), lenCodec.encode(valueBytes.length), valueBytes);
    }

    private byte[] encode(final Collection<TLV> tlvs) {
        final var out = new ByteArrayOutputStream();
        for (final var tlv : tlvs) {
            out.writeBytes(encode(tlv));
        }
        return out.toByteArray();
    }
}
