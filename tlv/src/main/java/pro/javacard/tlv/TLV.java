package pro.javacard.tlv;

import java.nio.ByteBuffer;
import java.util.*;

// A single TLV holding either a primitive or constructed tag
public final class TLV {
    private final Tag tag;
    private final byte[] value;
    private final List<TLV> children;
    private TLV parent;

    TLV(Tag tag, byte[] value, List<TLV> children) {
        this(tag, value, children, null);
    }

    private TLV(Tag tag, byte[] value, List<TLV> children, TLV parent) {
        this.tag = Objects.requireNonNull(tag, "tag cannot be null");
        this.value = value;
        this.children = children == null ? new ArrayList<>() : children;
        this.parent = parent;
    }

    // Factory methods
    public static TLV of(Tag tag, byte[] value) {
        return new TLV(tag, value.clone(), null, null);
    }

    public static TLV of(String tag, byte[] value) {
        return new TLV(Tag.ber(tag), value.clone(), null, null);
    }

    public static TLV of(Tag tag, TLV... tlvs) {
        return of(tag, Arrays.asList(tlvs));
    }

    public static TLV of(Tag tag, Collection<TLV> tlvs) {
        Objects.requireNonNull(tag, "tag");
        var children = new ArrayList<TLV>(tlvs.size());
        var parent = new TLV(tag, null, children, null);
        for (var tlv : tlvs) {
            Objects.requireNonNull(tlv, "child TLV");
            tlv.parent = parent;
            children.add(tlv);
        }
        return parent;
    }

    // Fluent builder for constructed TLV
    public static TLV build(Tag tag) {
        Objects.requireNonNull(tag, "tag");
        return new TLV(tag, null, new ArrayList<>(), null);
    }

    public static TLV build(String tagHex) {
        return build(Tag.ber(tagHex));
    }

    public Tag tag() {
        return tag;
    }

    public byte[] value() {
        return value == null ? null : value.clone();
    }

    public List<TLV> children() {
        return Collections.unmodifiableList(children);
    }

    public boolean hasChildren() {
        return !children.isEmpty();
    }

    // Navigation
    public TLV find(Tag tag) {
        if (this.tag.equals(tag)) {
            return this;
        }
        for (var t : children) {
            var r = t.find(tag);
            if (r != null) {
                return r;
            }
        }
        return null;
    }

    public TLV find(Tag tag, int maxDepth) {
        return find(tag, maxDepth, 0);
    }

    private TLV find(Tag tag, int maxDepth, int depth) {
        if (this.tag.equals(tag)) {
            return this;
        }
        if (maxDepth >= 0 && depth >= maxDepth) {
            return null;
        }
        for (var t : children) {
            var r = t.find(tag, maxDepth, depth + 1);
            if (r != null) {
                return r;
            }
        }
        return null;
    }

    public List<TLV> findAll(Tag t) {
        List<TLV> result = new ArrayList<>();
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
    public static Optional<TLV> find(List<TLV> list, Tag tag) {
        for (var tlv : list) {
            var r = tlv.find(tag);
            if (r != null) return Optional.of(r);
        }
        return Optional.empty();
    }

    public static List<TLV> findAll(List<TLV> list, Tag tag) {
        var result = new ArrayList<TLV>();
        for (var tlv : list) {
            result.addAll(tlv.findAll(tag));
        }
        return result;
    }

    // Fluent builder methods
    public TLV add(TLV tlv) {
        Objects.requireNonNull(tlv, "tlv");
        if (value != null) {
            throw new IllegalStateException("Cannot add children to primitive TLV");
        }
        tlv.parent = this;
        children.add(tlv);
        return this;
    }

    public TLV add(Tag childTag, byte[] value) {
        Objects.requireNonNull(childTag, "childTag");
        Objects.requireNonNull(value, "value");
        return add(TLV.of(childTag, value));
    }

    public TLV add(String childTagHex, byte[] value) {
        Objects.requireNonNull(childTagHex, "childTagHex");
        Objects.requireNonNull(value, "value");
        return add(TLV.of(childTagHex, value));
    }

    public TLV add(byte[] childTagBytes, byte[] value) {
        Objects.requireNonNull(childTagBytes, "childTagBytes");
        Objects.requireNonNull(value, "value");
        return add(TLV.of(Tag.ber(childTagBytes), value));
    }

    public TLV addByte(Tag tag, byte value) {
        return add(tag, new byte[]{value});
    }

    public TLV addByte(String tag, byte value) {
        return add(tag, new byte[]{value});
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
    public static List<TLV> parse(byte[] data) {
        return TLVParser.parse(data, Tag.Type.BER);
    }

    public static List<TLV> parse(ByteBuffer buffer) {
        return TLVParser.parse(buffer, Tag.Type.BER);
    }

    public static TLV parseSingle(ByteBuffer buffer) {
        return TLVParser.parseOne(buffer, Tag.Type.BER);
    }

    // Visualization
    private static void visualize(TLV tlv, int indent, List<String> list) {
        if (tlv.hasChildren()) {
            list.add(" ".repeat(indent) + tlv.tag);
            int tagLen = tlv.tag.bytes().length;
            for (var t : tlv.children) {
                visualize(t, indent + tagLen * 2 + 2, list);
            }
        } else {
            list.add(" ".repeat(indent) + tlv.tag + " " + HexFormat.of().withUpperCase().formatHex(tlv.value));
        }
    }

    public List<String> visualize() {
        var result = new ArrayList<String>();
        visualize(this, 0, result);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
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
