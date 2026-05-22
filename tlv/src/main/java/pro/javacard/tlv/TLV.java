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
        return new TLV(tag, value.clone(), null, null);
    }

    public static TLV of(final String tag, final byte[] value) {
        return new TLV(Tag.ber(tag), value.clone(), null, null);
    }

    public static TLV of(final Tag tag, final TLV... tlvs) {
        return of(tag, Arrays.asList(tlvs));
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

    public static TLV build(final String tagHex) {
        return build(Tag.ber(tagHex));
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
        final var encoded = new ArrayList<byte[]>();
        var total = 0;
        for (var child : children) {
            final var bytes = child.encode();
            encoded.add(bytes);
            total += bytes.length;
        }
        final var result = new byte[total];
        var offset = 0;
        for (var bytes : encoded) {
            System.arraycopy(bytes, 0, result, offset, bytes.length);
            offset += bytes.length;
        }
        return result;
    }

    public List<TLV> children() {
        return Collections.unmodifiableList(children);
    }

    public boolean hasChildren() {
        return !children.isEmpty();
    }

    // Navigation
    // First TLV with this tag found anywhere below this node, or null
    public TLV find(final Tag tag) {
        final var queue = new ArrayDeque<TLV>(children);
        while (!queue.isEmpty()) {
            final var node = queue.poll();
            if (node.tag.equals(tag)) {
                return node;
            }
            queue.addAll(node.children);
        }
        return null;
    }

    // Direct children with this tag; deeper matches are not returned
    public List<TLV> findAll(final Tag t) {
        final var result = new ArrayList<TLV>();
        for (var child : children) {
            if (child.tag.equals(t)) {
                result.add(child);
            }
        }
        return result;
    }

    // The single direct child with this tag, if any; throws if more than one match
    public Optional<TLV> findOne(final Tag t) {
        final var matches = findAll(t);
        if (matches.size() > 1) {
            throw new IllegalArgumentException("Multiple matches for tag " + t);
        }
        return matches.stream().findFirst();
    }

    // Like find(Tag), but throws NoSuchElementException with the tag in the message
    public TLV require(final Tag tag) {
        return require(tag, null);
    }

    public TLV require(final Tag tag, final String context) {
        final var r = find(tag);
        if (r == null) {
            throw new NoSuchElementException(notFoundMessage(tag, context));
        }
        return r;
    }

    // Static helpers for List<TLV>
    // First TLV with this tag found anywhere in the list or below
    public static Optional<TLV> find(final List<TLV> list, final Tag tag) {
        final var queue = new ArrayDeque<TLV>(list);
        while (!queue.isEmpty()) {
            final var node = queue.poll();
            if (node.tag.equals(tag)) {
                return Optional.of(node);
            }
            queue.addAll(node.children);
        }
        return Optional.empty();
    }

    // Like find(List, Tag), but throws NoSuchElementException with the tag in the message
    public static TLV require(final List<TLV> list, final Tag tag) {
        return require(list, tag, null);
    }

    public static TLV require(final List<TLV> list, final Tag tag, final String context) {
        return find(list, tag).orElseThrow(() -> new NoSuchElementException(notFoundMessage(tag, context)));
    }

    private static String notFoundMessage(final Tag tag, final String context) {
        final var base = "Tag " + tag.toHex() + " not found";
        return context == null ? base : base + ": " + context;
    }

    // Top-level entries of the list with this tag; deeper matches are not returned
    public static List<TLV> findAll(final List<TLV> list, final Tag tag) {
        final var result = new ArrayList<TLV>();
        for (var tlv : list) {
            if (tlv.tag.equals(tag)) {
                result.add(tlv);
            }
        }
        return result;
    }

    // The single top-level entry of the list with this tag, if any; throws if more than one match
    public static Optional<TLV> findOne(final List<TLV> list, final Tag tag) {
        final var matches = findAll(list, tag);
        if (matches.size() > 1) {
            throw new IllegalArgumentException("Multiple matches for tag " + tag);
        }
        return matches.stream().findFirst();
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

    public TLV add(final String childTagHex, final byte[] value) {
        Objects.requireNonNull(childTagHex, "childTagHex");
        Objects.requireNonNull(value, "value");
        return add(TLV.of(childTagHex, value));
    }

    public TLV add(final byte[] childTagBytes, final byte[] value) {
        Objects.requireNonNull(childTagBytes, "childTagBytes");
        Objects.requireNonNull(value, "value");
        return add(TLV.of(Tag.ber(childTagBytes), value));
    }

    public TLV addByte(final Tag tag, final byte value) {
        return add(tag, new byte[] { value });
    }

    public TLV addByte(final String tag, final byte value) {
        return add(tag, new byte[] { value });
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

    // Parsing - convenience methods for BER-TLV
    public static List<TLV> parse(final byte[] data) {
        return TLVParser.parse(data, Tag.Type.BER);
    }

    public static List<TLV> parse(final ByteBuffer buffer) {
        return TLVParser.parse(buffer, Tag.Type.BER);
    }

    // Parse exactly one BER-TLV and advance the buffer past it
    public static TLV parseSingle(final ByteBuffer buffer) {
        return TLVParser.parseOne(buffer, Tag.Type.BER);
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
