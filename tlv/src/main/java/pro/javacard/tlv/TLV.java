// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.nio.ByteBuffer;
import java.util.*;

// A single TLV holding either a primitive or constructed tag
public final class TLV {
    private final Tag tag;
    private final byte[] value;
    private final List<TLV> children;
    private TLV parent;

    TLV(final Tag tag, final byte[] value, final List<TLV> children) {
        this(tag, value, children, null);
    }

    private TLV(final Tag tag, final byte[] value, final List<TLV> children, final TLV parent) {
        this.tag = Objects.requireNonNull(tag, "tag cannot be null");
        this.value = value;
        this.children = children == null ? new ArrayList<>() : children;
        this.parent = parent;
    }

    // Factory methods
    public static TLV of(final Tag tag, final byte[] value) {
        Objects.requireNonNull(value, "value cannot be null; use an empty array for an empty primitive or build(tag) for an empty constructed node");
        return new TLV(tag, value.clone(), null, null);
    }

    public static TLV of(final int tag, final byte[] value) {
        return of(Tag.ber(tag), value);
    }

    public static TLV of(final Tag tag, final TLV... tlvs) {
        return of(tag, Arrays.asList(tlvs));
    }

    public static TLV of(final int tag, final TLV... tlvs) {
        return of(Tag.ber(tag), tlvs);
    }

    public static TLV of(final Tag tag, final Collection<TLV> tlvs) {
        Objects.requireNonNull(tag, "tag");
        final var children = new ArrayList<TLV>(tlvs.size());
        final var parent = new TLV(tag, null, children, null);
        for (var tlv : tlvs) {
            Objects.requireNonNull(tlv, "child TLV");
            tlv.parent = parent;
            children.add(tlv);
        }
        return parent;
    }

    // Fluent builder for constructed TLV
    public static TLV build(final Tag tag) {
        Objects.requireNonNull(tag, "tag");
        return new TLV(tag, null, new ArrayList<>(), null);
    }

    public static TLV build(final int tag) {
        return build(Tag.ber(tag));
    }

    // No arguments yields an empty array, handy as an empty primitive value.
    public static byte[] ba(final int... bytes) {
        final var out = new byte[bytes.length];
        for (var i = 0; i < bytes.length; i++) {
            final var b = bytes[i];
            if ((b & ~0xFF) != 0) {
                throw new IllegalArgumentException("Byte value out of range: " + Integer.toHexString(b));
            }
            out[i] = (byte) b;
        }
        return out;
    }

    public Tag tag() {
        return tag;
    }

    public byte[] value() {
        if (value != null) {
            return value.clone();
        }
        if (children.isEmpty()) {
            return new byte[0];
        }
        return encode(children);
    }

    public TLVs children() {
        return TLVs.of(children);
    }

    public boolean hasChildren() {
        return !children.isEmpty();
    }

    // True for a constructed tag (even when empty), false for a primitive value
    public boolean isConstructed() {
        return value == null;
    }

    // Navigation
    // The single direct child with this tag; findAll is the multi-finder, TPath addresses deeper nodes
    public Optional<TLV> find(final Tag tag) {
        final var matches = findAll(tag);
        if (matches.size() > 1) {
            throw new IllegalArgumentException("Multiple matches for tag " + tag.toHex());
        }
        return matches.stream().findFirst();
    }

    // Direct children with this tag; deeper matches are not returned
    public TLVs findAll(final Tag t) {
        final var result = new ArrayList<TLV>();
        for (var child : children) {
            if (child.tag.equals(t)) {
                result.add(child);
            }
        }
        return TLVs.of(result);
    }

    // Integer tag overloads (Tag.ber handles 1-3 byte tags, e.g. 0x9F70)
    public Optional<TLV> find(final int tag) {
        return find(Tag.ber(tag));
    }

    public TLVs findAll(final int tag) {
        return findAll(Tag.ber(tag));
    }

    // The single top-level entry of the list with this tag: empty if none, throws if more than one
    public static Optional<TLV> find(final List<TLV> list, final Tag tag) {
        final var matches = findAll(list, tag);
        if (matches.size() > 1) {
            throw new IllegalArgumentException("Multiple matches for tag " + tag.toHex());
        }
        return matches.stream().findFirst();
    }

    // Top-level entries of the list with this tag; deeper matches are not returned
    public static TLVs findAll(final List<TLV> list, final Tag tag) {
        final var result = new ArrayList<TLV>();
        for (var tlv : list) {
            if (tlv.tag.equals(tag)) {
                result.add(tlv);
            }
        }
        return TLVs.of(result);
    }

    // Integer tag overloads for the list helpers
    public static Optional<TLV> find(final List<TLV> list, final int tag) {
        return find(list, Tag.ber(tag));
    }

    public static TLVs findAll(final List<TLV> list, final int tag) {
        return findAll(list, Tag.ber(tag));
    }

    // Fluent builder methods
    public TLV add(final TLV tlv) {
        Objects.requireNonNull(tlv, "tlv");
        if (value != null) {
            throw new IllegalStateException("Cannot add children to primitive TLV");
        }
        tlv.parent = this;
        children.add(tlv);
        return this;
    }

    public TLV add(final Tag childTag, final byte[] value) {
        Objects.requireNonNull(childTag, "childTag");
        Objects.requireNonNull(value, "value");
        return add(TLV.of(childTag, value));
    }

    public TLV add(final int childTag, final byte[] value) {
        Objects.requireNonNull(value, "value");
        return add(TLV.of(childTag, value));
    }

    public TLV add(final byte[] childTagBytes, final byte[] value) {
        Objects.requireNonNull(childTagBytes, "childTagBytes");
        Objects.requireNonNull(value, "value");
        return add(TLV.of(Tag.ber(childTagBytes), value));
    }

    public TLV end() {
        if (parent == null) {
            throw new IllegalStateException("No parent to return to");
        }
        return parent;
    }

    // Encoding
    public byte[] encode() {
        return TLVEncoder.encode(this);
    }

    // Concatenate encoded TLVs (no parent tag wrapping)
    public static byte[] encode(TLV... tlvs) {
        return encode(Arrays.asList(tlvs));
    }

    public static byte[] encode(Collection<TLV> tlvs) {
        var parts = new ArrayList<byte[]>(tlvs.size());
        var total = 0;
        for (var tlv : tlvs) {
            var bytes = tlv.encode();
            parts.add(bytes);
            total += bytes.length;
        }
        var result = new byte[total];
        var offset = 0;
        for (var bytes : parts) {
            System.arraycopy(bytes, 0, result, offset, bytes.length);
            offset += bytes.length;
        }
        return result;
    }

    // Parsing - convenience methods for BER-TLV
    private static final TLVParser BER = TLVParser.of(Tag.Codec.BER, Len.Codec.BER, true);

    public static TLVs parse(final byte[] data) {
        return BER.parse(data);
    }

    public static TLVs parse(final ByteBuffer buffer) {
        return BER.parse(buffer);
    }

    // Parse exactly one BER-TLV and advance the buffer past it
    public static TLV parseSingle(final ByteBuffer buffer) {
        return BER.parseOne(buffer);
    }

    // Visualization
    private static void visualize(final TLV tlv, final int indent, final List<String> list) {
        if (tlv.hasChildren()) {
            list.add(" ".repeat(indent) + tlv.tag);
            final var tagLen = tlv.tag.bytes().length;
            for (var t : tlv.children) {
                visualize(t, indent + tagLen * 2 + 2, list);
            }
        } else {
            list.add(" ".repeat(indent) + tlv.tag + " " + HexFormat.of().withUpperCase().formatHex(tlv.value()));
        }
    }

    public List<String> visualize() {
        final var result = new ArrayList<String>();
        visualize(this, 0, result);
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        return obj instanceof TLV other
                && this.tag.equals(other.tag)
                && Arrays.equals(this.value, other.value)
                && this.children.equals(other.children);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.tag, Arrays.hashCode(this.value), this.children);
    }
}
