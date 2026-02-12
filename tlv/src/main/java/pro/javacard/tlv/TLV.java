/*
 * Copyright (c) 2025 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
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
    public TLV find(final Tag tag) {
        if (this.tag.equals(tag)) {
            return this;
        }
        for (var t : children) {
            final var r = t.find(tag);
            if (r != null) {
                return r;
            }
        }
        return null;
    }

    public TLV find(final Tag tag, final int maxDepth) {
        return find(tag, maxDepth, 0);
    }

    private TLV find(final Tag tag, final int maxDepth, final int depth) {
        if (this.tag.equals(tag)) {
            return this;
        }
        if (maxDepth >= 0 && depth >= maxDepth) {
            return null;
        }
        for (var t : children) {
            final var r = t.find(tag, maxDepth, depth + 1);
            if (r != null) {
                return r;
            }
        }
        return null;
    }

    public List<TLV> findAll(final Tag t) {
        final var result = new ArrayList<TLV>();
        if (this.tag.equals(t)) {
            result.add(this);
            return result;
        }
        for (var tlv : children) {
            result.addAll(tlv.findAll(t));
        }
        return result;
    }

    // Static helpers for List<TLV>
    public static Optional<TLV> find(final List<TLV> list, final Tag tag) {
        for (var tlv : list) {
            final var r = tlv.find(tag);
            if (r != null) {
                return Optional.of(r);
            }
        }
        return Optional.empty();
    }

    public static List<TLV> findAll(final List<TLV> list, final Tag tag) {
        final var result = new ArrayList<TLV>();
        for (var tlv : list) {
            result.addAll(tlv.findAll(tag));
        }
        return result;
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
