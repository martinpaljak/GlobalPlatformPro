// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.util.AbstractList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

// Same as List<TLV>, but with handy utility functions baked in.
public final class TLVs extends AbstractList<TLV> {
    private final List<TLV> backing;

    private TLVs(final List<TLV> list) {
        this.backing = List.copyOf(list);
    }

    public static TLVs of(final List<TLV> list) {
        return new TLVs(list);
    }

    public static TLVs of(final TLV... tlvs) {
        return new TLVs(List.of(tlvs));
    }

    public static TLVs parse(final byte[] data) {
        return TLV.parse(data);
    }

    // Render the bytes - one TLV or several concatenated - as indented "[tag] value" lines for logging
    public static List<String> visualize(final byte[] data) {
        return parse(data).stream().flatMap(t -> t.visualize().stream()).toList();
    }

    @Override
    public TLV get(final int i) {
        return backing.get(i);
    }

    @Override
    public int size() {
        return backing.size();
    }

    // Encode all entries back to bytes (inverse of parse)
    public byte[] encode() {
        return TLV.encode(this);
    }

    // --- find ---
    public Optional<TLV> find(final TPath path) {
        return TPath.find(this, path);
    }

    public Optional<TLV> find(final int... tags) {
        return TPath.find(this, tags);
    }

    public Optional<TLV> find(final Tag... tags) {
        return TPath.find(this, tags);
    }

    // --- findAll: every node matching the last segment, reached by following the earlier segments by first match.
    // Returns a TLVs so the result is both a List and chainable. ---
    public TLVs findAll(final TPath path) {
        return TPath.findAll(this, path);
    }

    public TLVs findAll(final int... tags) {
        return TPath.findAll(this, tags);
    }

    public TLVs findAll(final Tag... tags) {
        return TPath.findAll(this, tags);
    }

    // --- set ---
    public TLVs set(final TPath path, final byte[] value) {
        return TPath.set(this, path, value);
    }

    public TLVs set(final int t0, final byte[] value) {
        return TPath.set(this, t0, value);
    }

    public TLVs set(final int t0, final int t1, final byte[] value) {
        return TPath.set(this, t0, t1, value);
    }

    public TLVs set(final int t0, final int t1, final int t2, final byte[] value) {
        return TPath.set(this, t0, t1, t2, value);
    }

    // --- compute: read-modify-write of a primitive leaf, like Map.compute. remap gets the current
    // value or null when absent, and a null result deletes the leaf. ---
    public TLVs compute(final TPath path, final Function<byte[], byte[]> remap) {
        final var existing = find(path);
        final var next = remap.apply(existing.map(TLV::value).orElse(null));
        if (next == null) {
            return existing.isPresent() ? delete(path) : this;
        }
        return set(path, next);
    }

    // --- add (single-int level lives on TPath.add(List,int,TLV); add(int,TLV) here would clash
    //          with List.add(int index, TLV element)) ---
    public TLVs add(final TPath path, final TLV child) {
        return TPath.add(this, path, child);
    }

    public TLVs add(final int t0, final int t1, final TLV child) {
        return TPath.add(this, t0, t1, child);
    }

    public TLVs add(final int t0, final int t1, final int t2, final TLV child) {
        return TPath.add(this, t0, t1, t2, child);
    }

    // --- delete ---
    public TLVs delete(final TPath path) {
        return TPath.delete(this, path);
    }

    public TLVs delete(final int... tags) {
        return TPath.delete(this, tags);
    }

    public TLVs delete(final Tag... tags) {
        return TPath.delete(this, tags);
    }
}
