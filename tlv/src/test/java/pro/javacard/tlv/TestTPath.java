// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.HexFormat;
import java.util.List;
import java.util.stream.Collectors;

class TestTPath {
    static byte[] hex(final String s) {
        return HexFormat.of().parseHex(s.replaceAll("\\s", ""));
    }

    static List<Tag> tags(final List<TLV> nodes) {
        return nodes.stream().map(TLV::tag).collect(Collectors.toList());
    }

    // set, add and delete over one tree, asserting order preservation and purity
    @Test
    public void editLifecycle() {
        final var tree = List.of(
                TLV.build(0x6F)
                        .add(0x84, hex("A0000001510000"))
                        .add(TLV.build(0xA5)
                                .add(0x9F08, hex("0200"))
                                .add(0x9F65, hex("FF"))));
        final var before = TLV.encode(tree);
        final var roots = TLVs.of(tree);

        // operations are threaded through the int, Tag and TPath construction styles
        final var r = roots
                .set(0x6F, 0xA5, 0x9F08, hex("0210")) // int: replace existing primitive
                .set(TPath.of(0x6F, 0xA5, 0x9F02), hex("0000000A")) // TPath: upsert leaf into constructed
                .set(0x6F, 0x70, 0x9F1F, hex("AA")) // int: create missing intermediate chain
                .add(TPath.of(0x6F, 0xA5), TLV.of(0x9F65, hex("EE"))) // TPath: append a duplicate-tag child
                .add(0x6F, 0x71, TLV.of(0x9F1E, hex("BB"))) // int: add, upserting the parent chain
                .delete(0x6F, 0x84) // int: delete an existing node
                .set(0x80, hex("9000")); // int: single-segment root upsert

        // edits landed (read back through int, Tag and TPath styles)
        Assert.assertEquals(r.find(0x6F, 0xA5, 0x9F08).get().value(), hex("0210"));
        Assert.assertEquals(r.find(TPath.of(0x6F, 0xA5, 0x9F02)).get().value(), hex("0000000A"));
        Assert.assertEquals(r.find(Tag.ber("6F"), Tag.ber("70"), Tag.ber("9F1F")).get().value(), hex("AA"));
        Assert.assertTrue(r.find(0x6F, 0x70).get().isConstructed());
        Assert.assertEquals(r.find(0x6F, 0x71, 0x9F1E).get().value(), hex("BB"));
        Assert.assertEquals(r.find(0x80).get().value(), hex("9000"));
        Assert.assertTrue(r.find(0x6F, 0x84).isEmpty());

        // order preserved: substitutions stay in place, creations append
        Assert.assertEquals(tags(r.find(0x6F, 0xA5).get().children()),
                List.of(Tag.ber("9F08"), Tag.ber("9F65"), Tag.ber("9F02"), Tag.ber("9F65")));
        Assert.assertEquals(tags(r.find(0x6F).get().children()),
                List.of(Tag.ber("A5"), Tag.ber("70"), Tag.ber("71")));
        Assert.assertEquals(tags(r), List.of(Tag.ber("6F"), Tag.ber("80")));

        // find addresses at most one: the two 9F65 under A5 make the path ambiguous
        Assert.expectThrows(IllegalArgumentException.class, () -> r.find(0x6F, 0xA5, 0x9F65));

        // purity: original bytes and original values untouched
        Assert.assertEquals(TLV.encode(tree), before);
        Assert.assertEquals(roots.find(0x6F, 0xA5, 0x9F08).get().value(), hex("0200"));
    }

    // Path construction styles, the fluent predicate, find/findAll hits/misses, and the no-op delete.
    @Test
    public void pathsAndFind() {
        // 0x9F65 maps to the two-byte tag [9F 65]
        Assert.assertEquals(Tag.ber(0x9F65).bytes(), hex("9F65"));

        // int and Tag construction (and the fluent builder) produce equal paths
        final var b = TPath.of(0x6F, 0xA5, 0x9F65).segments();
        final var c = TPath.of(Tag.ber("6F"), Tag.ber("A5"), Tag.ber("9F65")).segments();
        final var d = TPath.root().tag(0x6F).tag(0xA5).tag(Tag.ber("9F65")).segments();
        Assert.assertEquals(c, b);
        Assert.assertEquals(d, b);

        // built by parsing encoded bytes back into a tree
        final var bytes = TLV.build(0x6F).add(TLV.build(0xA5)
                .add(0x9F65, hex("AA"))
                .add(0x9F65, hex("BB"))).encode();
        final var roots = TLVs.parse(bytes);

        // parse then encode is a symmetric round-trip
        Assert.assertEquals(roots.encode(), bytes);

        Assert.assertTrue(roots.find(TPath.root()).isEmpty()); // empty path addresses nothing
        Assert.assertTrue(roots.find(0x6F, 0x99).isEmpty()); // miss
        // find addresses at most one: duplicate 9F65 under A5 is ambiguous -> throws (use where/findAll)
        Assert.expectThrows(IllegalArgumentException.class, () -> roots.find(Tag.ber("6F"), Tag.ber("A5"), Tag.ber("9F65")));

        // a value predicate narrows which of the duplicate leaves is selected
        final var second = TPath.of(0x6F, 0xA5).tag(0x9F65).where(v -> v.length == 1 && v[0] == (byte) 0xBB);
        Assert.assertEquals(roots.find(second).get().value(), hex("BB"));

        // findAll returns every leaf matching the last segment, reached by first match at each earlier segment
        Assert.assertEquals(tags(roots.findAll(0x6F, 0xA5, 0x9F65)), List.of(Tag.ber("9F65"), Tag.ber("9F65")));
        Assert.assertEquals(roots.findAll(0x6F).size(), 1); // single-segment, top level
        Assert.assertTrue(roots.findAll(0x6F, 0x99).isEmpty()); // last segment matches nothing
        Assert.assertTrue(roots.findAll(0x6F, 0x99, 0x9F65).isEmpty()); // spine breaks mid-walk
        Assert.assertTrue(roots.findAll(TPath.root()).isEmpty()); // empty path
        Assert.assertEquals(roots.findAll(second).size(), 1); // predicate filters the multi-match

        // a predicate cannot synthesize a value: upsert-creation is tag-only and ignores it
        final var created = roots.set(TPath.of(0x6F).tag(0xB5).where(v -> false), hex("01"));
        Assert.assertEquals(created.find(0x6F, 0xB5).get().value(), hex("01"));

        // delete of an absent path is a no-op returning an equal, fresh tree
        Assert.assertEquals(roots.delete(0x6F, 0x99), roots);
    }

    // compute: functional read-modify-write - remap sees the current value (or null when absent),
    // its result replaces, creates or (when null) deletes the leaf.
    @Test
    public void compute() {
        final var roots = TLVs.of(TLV.of(0x82, hex("AABB")));

        // a present leaf is transformed from its current value (OR a bit into the first byte)
        Assert.assertEquals(roots.compute(TPath.of(0x82), v -> {
            final var r = v.clone();
            r[0] |= 0x01;
            return r;
        }).find(0x82).orElseThrow().value(), hex("ABBB"));

        // an absent leaf is created: remap sees null and returns a value
        Assert.assertEquals(roots.compute(TPath.of(0x87), v -> v == null ? hex("2020") : v)
                .find(0x87).orElseThrow().value(), hex("2020"));

        // an absent deep path is created through the set machinery
        Assert.assertEquals(roots.compute(TPath.of(0x6F, 0xC9), v -> hex("01"))
                .find(0x6F, 0xC9).orElseThrow().value(), hex("01"));

        // a null result on a present leaf deletes it (Map.compute parity)
        Assert.assertTrue(roots.compute(TPath.of(0x82), v -> null).find(0x82).isEmpty());

        // a null result on an absent leaf is a no-op that returns the receiver unchanged
        Assert.assertSame(roots.compute(TPath.of(0x99), v -> null), roots);
    }

    // Interface contract: invalid inputs and forbidden edits throw.
    @Test
    public void contracts() {
        final var roots = TLVs.of(
                TLV.build(0x6F)
                        .add(0x84, hex("AABB"))
                        .add(TLV.build(0xA5).add(0x9F08, hex("00"))));

        // set must not silently replace a constructed subtree
        Assert.expectThrows(IllegalArgumentException.class, () -> roots.set(0x6F, 0xA5, hex("00")));
        // compute addresses a primitive leaf; a constructed target throws via set
        Assert.expectThrows(IllegalArgumentException.class, () -> roots.compute(TPath.of(0x6F, 0xA5), v -> hex("00")));
        // add must not target a primitive
        Assert.expectThrows(IllegalStateException.class, () -> roots.add(0x6F, 0x84, TLV.of(0x9F01, hex("00"))));
        // cannot descend through a primitive
        Assert.expectThrows(IllegalStateException.class, () -> roots.set(0x6F, 0x84, 0x9F01, hex("00")));
        // an empty path addresses no node to edit
        Assert.expectThrows(IllegalArgumentException.class, () -> roots.set(TPath.root(), hex("00")));
        Assert.expectThrows(IllegalArgumentException.class, () -> roots.delete(TPath.root()));
        // a predicate needs a segment to constrain
        Assert.expectThrows(IllegalStateException.class, () -> TPath.root().where(v -> true));
        // null payloads are rejected
        Assert.expectThrows(NullPointerException.class, () -> roots.set(TPath.of(0x6F), null));
    }
}
