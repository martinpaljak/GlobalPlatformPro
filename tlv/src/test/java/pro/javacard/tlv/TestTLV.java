// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.nio.ByteBuffer;
import java.util.*;

class TestTLV {
    static byte[] hex(final String s) {
        return HexFormat.of().parseHex(s.replaceAll("\\s", ""));
    }

    @Test
    public void testConstruction() {
        final var tlv = TLV.of(0x9F45, hex("01020304"));
        Assert.assertEquals(tlv.encode(), hex("9F450401020304"));
        final var tlv1 = TLV.build(0x7F42)
                .add(0x9F45, hex("222222"))
                .add(0x9F46, hex("333333"))
                .add(0x9F45, hex("444444"));

        final var bin = tlv1.encode();
        Assert.assertEquals(bin, hex("7F42129F45032222229F46033333339F4503444444"));

        final var result = TLV.parse(bin);
        final var strings = result.get(0).visualize();
        Assert.assertEquals(strings,
                List.of("[7F42]", "      [9F45] 222222", "      [9F46] 333333", "      [9F45] 444444"));

        // 9F45 appears twice under 7F42: find is ambiguous, findAll returns both
        Assert.expectThrows(IllegalArgumentException.class, () -> result.find(0x7F42, 0x9F45));
        final var matches = result.get(0).findAll(Tag.ber("9f45"));
        Assert.assertEquals(matches.size(), 2);
        Assert.assertEquals(matches.get(0).value(), hex("222222"));

        // integer tag overloads mirror the Tag versions; find resolves a unique tag
        Assert.assertEquals(result.get(0).findAll(0x9F45).size(), 2);
        Assert.assertEquals(result.get(0).find(0x9F46).orElseThrow().value(), hex("333333"));
    }

    @Test
    public void testTagFactories() {
        // Single byte tags
        final var tag1 = Tag.ber(0x66);
        Assert.assertEquals(tag1.bytes(), new byte[] { 0x66 });

        // Two byte tags
        final var tag2 = Tag.ber(0x9F, 0x70);
        Assert.assertEquals(tag2.bytes(), new byte[] { (byte) 0x9F, 0x70 });
    }

    @Test
    public void testAddByte() {
        final var tlv = TLV.build(Tag.ber(0x70))
                .add(Tag.ber(0x80), TLV.ba(0x01))
                .add(0x81, TLV.ba(0xFF));

        final var encoded = tlv.encode();
        Assert.assertEquals(encoded, hex("70 06 80 01 01 81 01 FF"));
    }

    @Test
    public void testParseList() {
        final var data = hex("80010181010282010383010484010585010686010787010888010989010A8A010B");
        final var list = TLV.parse(data);
        Assert.assertEquals(list.size(), 11);
        Assert.assertEquals(list.get(0).tag(), Tag.ber(0x80));
        Assert.assertEquals(list.get(10).tag(), Tag.ber(0x8A));
    }

    @Test
    public void testSimpleTag() {
        final var tag = Tag.simple((byte) 0x01);
        Assert.assertEquals(tag.bytes(), new byte[] { 0x01 });
        Assert.assertEquals(tag.toString(), "[01]");

        // Test invalid simple tags
        Assert.assertThrows(IllegalArgumentException.class, () -> Tag.simple((byte) 0x00));
        Assert.assertThrows(IllegalArgumentException.class, () -> Tag.simple((byte) 0xFF));

        // Test construction via factories
        final var tlv = TLV.of(Tag.simple((byte) 0x10), new byte[] { 0x01 });
        Assert.assertEquals(tlv.encode(), hex("10 01 01")); // Simple TLV uses 1 byte length if < 0xFF
    }

    @Test
    public void testDGITag() {
        final var tag = Tag.dgi(0x1234);
        Assert.assertEquals(tag.bytes(), new byte[] { 0x12, 0x34 });
        Assert.assertEquals(tag.toString(), "[1234]");

        // Test invalid DGI tags
        Assert.assertThrows(IllegalArgumentException.class, () -> Tag.dgi(-1));
        Assert.assertThrows(IllegalArgumentException.class, () -> Tag.dgi(0x10000));
    }

    @Test
    public void testLenBer() {
        // Test edge cases for BER length
        Assert.assertThrows(IllegalArgumentException.class, () -> Len.ber(-1));
        Assert.assertEquals(Len.ber(0), hex("00"));
        Assert.assertEquals(Len.ber(127), hex("7F"));
        Assert.assertEquals(Len.ber(128), hex("81 80"));
        Assert.assertEquals(Len.ber(255), hex("81 FF"));
        Assert.assertEquals(Len.ber(256), hex("82 01 00"));
        Assert.assertEquals(Len.ber(65535), hex("82 FF FF"));
        Assert.assertEquals(Len.ber(65536), hex("83 01 00 00"));
        Assert.assertThrows(IllegalArgumentException.class, () -> Len.ber(0x1000000)); // Too large for implementation
                                                                                       // (max 3 bytes logic in code)
    }

    @Test
    public void testLenExt() {
        // Test edge cases for Extended length (SimpleTLV/DGI)
        Assert.assertThrows(IllegalArgumentException.class, () -> Len.ext(-1));
        Assert.assertEquals(Len.ext(0), hex("00"));
        Assert.assertEquals(Len.ext(254), hex("FE"));
        Assert.assertEquals(Len.ext(255), hex("FF 00 FF")); // 0xFF is escape, then 2 bytes length
        Assert.assertEquals(Len.ext(65535), hex("FF FF FF"));
        Assert.assertThrows(IllegalArgumentException.class, () -> Len.ext(65536));
    }

    @Test
    public void testBERTagValidation() {
        // Null check
        Assert.assertThrows(NullPointerException.class, () -> new BERTag(null));
        // Empty
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(new byte[0]));
        // Too long
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(new byte[5]));

        // A single byte tag (bits 1-5 not all 1) must be exactly one byte
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(new byte[] { (byte) 0x00, (byte) 0x01 }));

        // Missing continuation bit
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(hex("9F 01 02"))); // Middle byte 01
                                                                                                // missing 0x80

        // Last byte has continuation bit
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(hex("9F 82"))); // Last byte 82 has 0x80
    }

    @Test
    public void testTLVMethods() {
        final var t = TLV.build(0x9F45).add(0x81, hex("01"));

        // Children
        Assert.assertTrue(t.hasChildren());
        Assert.assertEquals(t.children().size(), 1);
        Assert.assertEquals(t.value(), t.children().get(0).encode());

        // Find: first direct child with the tag (does not descend)
        Assert.assertTrue(t.find(Tag.ber("81")).isPresent());
        Assert.assertTrue(t.find(Tag.ber("82")).isEmpty());

        // Direct only: a nested tag is not matched, and self is never a candidate
        final var deep = TLV.build(0x7F01).add(t);
        Assert.assertTrue(deep.find(Tag.ber("9F45")).isPresent()); // direct child
        Assert.assertTrue(deep.find(Tag.ber("81")).isEmpty());     // nested under 9F45, not direct
        Assert.assertTrue(deep.find(Tag.ber("7F01")).isEmpty());   // self never a candidate

        // Check "end"
        Assert.assertEquals(t.children().get(0).end(), t);
        // t has been added to 'deep', so t.parent is deep.
        Assert.assertEquals(t.end(), deep);

        // New root TLV for exception check
        final var root = TLV.build(0x9F45);
        Assert.assertThrows(IllegalStateException.class, () -> root.end()); // No parent

        // Add to primitive
        final var p = TLV.of(0x81, hex("01"));
        Assert.assertThrows(IllegalStateException.class, () -> p.add(0x82, hex("02")));
    }

    @Test
    public void testEqualsAndHashCode() {
        final var t1 = TLV.of(0x9F45, hex("01"));
        final var t2 = TLV.of(0x9F45, hex("01"));
        final var t3 = TLV.of(0x9F46, hex("01"));

        Assert.assertEquals(t1, t1);
        Assert.assertEquals(t1, t2);
        Assert.assertNotEquals(t1, t3);
        Assert.assertNotEquals(t1, null);
        Assert.assertNotEquals(t1, "string");

        Assert.assertEquals(t1.hashCode(), t2.hashCode());
    }

    @Test
    public void testParsingErrors() {
        // Buffer underflow
        Assert.assertThrows(TLVParseException.class, () -> TLV.parse(hex("9F")));

        // Length overflow in BER: 84 is four length bytes, three is the maximum
        Assert.assertThrows(TLVParseException.class, () -> TLV.parse(hex("9F 84 FF FF FF FF")));
    }

    @Test
    public void testParseSimple() {
        // Simple TLV: Tag 01, Length 01, Value 01
        final var data = hex("01 01 01");
        final var list = TLVParser.of(Tag.Codec.SINGLE_BYTE, Len.Codec.EXT, false).parse(data);
        Assert.assertEquals(list.size(), 1);
        Assert.assertTrue(list.get(0).tag() instanceof SimpleTag);
        Assert.assertEquals(list.get(0).tag(), Tag.simple((byte) 0x01));
    }

    @Test
    public void testParseDGI() {
        // DGI TLV: Tag 1234, Length 01, Value 01. Length in DGI is Extended (same as
        // Simple)
        final var data = hex("12 34 01 01");
        final var list = TLVParser.of(Tag.Codec.DGI, Len.Codec.EXT, false).parse(data);
        Assert.assertEquals(list.size(), 1);
        Assert.assertTrue(list.get(0).tag() instanceof DGITag);
        Assert.assertEquals(list.get(0).tag(), Tag.dgi(0x1234));
    }

    @Test
    public void testUtilityConstructors() throws Exception {
        // Cover private constructors for 100% coverage (TLVParser's is exercised via of())
        final var classes = new Class<?>[] { Len.class, TLVEncoder.class };
        for (Class<?> cls : classes) {
            final var constructor = cls.getDeclaredConstructor();
            constructor.setAccessible(true);
            constructor.newInstance();
        }
    }

    @Test
    public void testLenBufferMethods() {
        // Len.ber(ByteBuffer) cases
        // 1 byte length
        Assert.assertEquals(Len.ber(ByteBuffer.wrap(hex("7F"))), 127);
        // 2 byte length (81 80)
        Assert.assertEquals(Len.ber(ByteBuffer.wrap(hex("81 80"))), 128);
        // 3 byte length (82 01 00)
        Assert.assertEquals(Len.ber(ByteBuffer.wrap(hex("82 01 00"))), 256);
        // Invalid length (84 ...) -> > 3 bytes
        Assert.assertThrows(IllegalArgumentException.class,
                () -> Len.ber(ByteBuffer.wrap(hex("84 00 00 00 00"))));

        // Len.ext(ByteBuffer) cases
        Assert.assertEquals(Len.ext(ByteBuffer.wrap(hex("FE"))), 254);
        Assert.assertEquals(Len.ext(ByteBuffer.wrap(hex("FF 00 FF"))), 255);
    }

    @Test
    public void testTagFactoriesAdditional() {
        // Cover Tag.ber(int) and Tag.ber(int, int)
        Assert.assertEquals(Tag.ber(0x9F).bytes(), new byte[] { (byte) 0x9F });
        Assert.assertEquals(Tag.ber(0x9F, 0x01).bytes(), new byte[] { (byte) 0x9F, (byte) 0x01 });
        // Tag.ber(String) with spaces
        Assert.assertEquals(Tag.ber("9F 01").bytes(), new byte[] { (byte) 0x9F, (byte) 0x01 });
    }

    @Test
    public void testVisualizerRecursive() {
        final var t = TLV.build(0xE0).add(0x81, hex("01")).add(TLV.build(0xE1).add(0x82, hex("02")));
        final var vis = t.visualize();
        Assert.assertTrue(vis.size() > 0);
        Assert.assertTrue(vis.stream().anyMatch(s -> s.contains("[E0]")));
        Assert.assertTrue(vis.stream().anyMatch(s -> s.contains("[81]")));
        Assert.assertTrue(vis.stream().anyMatch(s -> s.contains("[E1]")));
        Assert.assertTrue(vis.stream().anyMatch(s -> s.contains("[82]")));
    }

    @Test
    public void byteArrays() {
        Assert.assertEquals(TLV.ba(), new byte[0]);
        Assert.assertEquals(TLV.ba(0x00), new byte[] { 0x00 });
        Assert.assertEquals(TLV.ba(0xFF), new byte[] { (byte) 0xFF });
        Assert.assertEquals(TLV.ba(0x34, 0x22), new byte[] { 0x34, 0x22 });
        Assert.assertEquals(TLV.ba(0x01, 0x02, 0x03), new byte[] { 0x01, 0x02, 0x03 });
        Assert.expectThrows(IllegalArgumentException.class, () -> TLV.ba(0x100));
        Assert.expectThrows(IllegalArgumentException.class, () -> TLV.ba(-1));
        Assert.expectThrows(IllegalArgumentException.class, () -> TLV.ba(0x10, 0x100));
    }

    @Test
    public void testCoverageCompletion() {
        // Offset/length parsing via a ByteBuffer slice: start at index 1, length 3 (01 01 01)
        final var data = hex("00 01 01 01");
        final var list = TLVParser.of(Tag.Codec.SINGLE_BYTE, Len.Codec.EXT, false).parse(ByteBuffer.wrap(data, 1, 3));
        Assert.assertEquals(list.size(), 1);
        Assert.assertEquals(list.get(0).tag(), Tag.simple((byte) 0x01));

        // TLV.of(Tag, Collection)
        final var children = List.of(TLV.of(0x81, hex("01")));
        final var t = TLV.of(Tag.ber("E0"), children);
        Assert.assertEquals(t.children().size(), 1);

        // TLVs path find replaces the old recursive static find
        final var list2 = List.of(t);
        final var roots = TLVs.of(list2);
        Assert.assertTrue(roots.find(0xE0, 0x81).isPresent()); // nested, addressed by path
        Assert.assertTrue(roots.find(0x81).isEmpty());         // not a top-level entry

        Assert.assertEquals(TLV.findAll(list2, Tag.ber("E0")).size(), 1);
        Assert.assertEquals(TLV.findAll(list2, Tag.ber("81")).size(), 0);
        Assert.assertEquals(list2.get(0).findAll(Tag.ber("81")).size(), 1);
        Assert.assertEquals(list2.get(0).findAll(Tag.ber("82")).size(), 0);

        // find is the single-finder: present for one match, empty for none; direct/top-level only
        Assert.assertSame(TLV.find(list2, Tag.ber("E0")).get(), t);          // static, top-level
        Assert.assertTrue(TLV.find(list2, Tag.ber("81")).isEmpty());         // 81 is nested, not top-level
        Assert.assertTrue(list2.get(0).find(Tag.ber("81")).isPresent());     // instance, direct child of E0
        Assert.assertTrue(list2.get(0).find(Tag.ber("82")).isEmpty());

        // find throws on multiple matches; findAll is the multi-finder
        final var twoSame = TLV.of(Tag.ber("E1"),
                List.of(TLV.of(0x82, hex("01")), TLV.of(0x82, hex("02"))));
        Assert.assertThrows(IllegalArgumentException.class, () -> twoSame.find(Tag.ber("82")));
        Assert.assertEquals(twoSame.findAll(Tag.ber("82")).size(), 2);
        final var listTwoSame = List.of(TLV.of(0x83, hex("AA")), TLV.of(0x83, hex("BB")));
        Assert.assertThrows(IllegalArgumentException.class, () -> TLV.find(listTwoSame, Tag.ber("83")));

        // TLV.add(byte[], byte[])
        final var t2 = TLV.build(0xE0).add(hex("81"), hex("01"));
        Assert.assertTrue(t2.hasChildren());
    }

    @Test
    public void testTLVWrappers() {
        // TLV.parse(ByteBuffer)
        final var data = hex("9F 45 01 01");
        final var list = TLV.parse(ByteBuffer.wrap(data));
        Assert.assertEquals(list.size(), 1);
        Assert.assertEquals(list.get(0).tag(), Tag.ber("9F45"));

        // TLV.parseSingle(ByteBuffer)
        final var t = TLV.parseSingle(ByteBuffer.wrap(data));
        Assert.assertEquals(t.tag(), Tag.ber("9F45"));

        // TLV.of(Tag, TLV...) varargs
        final var child1 = TLV.of(0x81, hex("01"));
        final var child2 = TLV.of(0x82, hex("02"));
        final var parent = TLV.of(Tag.ber("E0"), child1, child2);
        Assert.assertEquals(parent.children().size(), 2);

        // TLV.of(int, TLV...) varargs
        final var parentInt = TLV.of(0xE0, child1, child2);
        Assert.assertEquals(parentInt.tag(), Tag.ber("E0"));
        Assert.assertEquals(parentInt.children().size(), 2);
    }

    @Test
    public void testPackagePrivateConstructor() {
        // Cover the package-private constructor TLV(Tag, byte[], List<TLV>)
        // which delegates to the 4-arg private one.
        final var t = new TLV(Tag.ber("9F01"), hex("01"), null);
        Assert.assertEquals(t.value().length, 1);
    }

    @Test
    public void testFindAllDirectChildren() {
        final var t = TLV.build(0xE0)
                .add(0x9F45, hex("01"))
                .add(0x9F45, hex("02"))
                .add(0x9F46, hex("03"));
        Assert.assertEquals(t.findAll(Tag.ber("9F45")).size(), 2);
        Assert.assertEquals(t.findAll(Tag.ber("9F46")).size(), 1);
        Assert.assertEquals(t.findAll(Tag.ber("E0")).size(), 0);
        Assert.assertTrue(TLV.of(0x9F45, hex("01")).findAll(Tag.ber("9F45")).isEmpty());
    }

    @Test
    public void testFindDirectChild() {
        final var deep = TLV.of(0xC0, hex("01"));
        final var shallow = TLV.of(0xC0, hex("02"));
        final var a0 = TLV.of(Tag.ber("A0"), TLV.of(Tag.ber("B0"), deep), shallow);
        // find returns the first direct child and never descends into B0 to reach 'deep'
        Assert.assertEquals(a0.find(Tag.ber("C0")), Optional.of(shallow));
    }

    @Test
    public void testFindAllNonRecursive() {
        final var direct = TLV.of(0xC0, hex("01"));
        final var nested = TLV.of(0xC0, hex("02"));
        final var e0 = TLV.of(Tag.ber("E0"), direct, TLV.of(Tag.ber("E1"), nested));
        Assert.assertEquals(e0.findAll(Tag.ber("C0")), List.of(direct));
    }

    @Test
    public void testEqualsDeep() {
        final var t1 = TLV.of(0x9F45, hex("01"));
        final var t2 = TLV.of(0x9F45, hex("02")); // Diff value
        Assert.assertNotEquals(t1, t2);

        final var c1 = TLV.of(Tag.ber("E0"), t1);
        final var c2 = TLV.of(Tag.ber("E0"), t2); // Diff child
        Assert.assertNotEquals(c1, c2);
    }

    @Test
    public void testOfWithNullChild() {
        final var list = new ArrayList<TLV>();
        list.add(null);
        Assert.assertThrows(NullPointerException.class, () -> TLV.of(Tag.ber("E0"), list));
    }

    @Test
    public void testThreeByteBERTag() {
        // 9F 81 01: first byte 9F, 81 continues, 01 ends
        final var tag = new BERTag(hex("9F 81 01"));
        Assert.assertNotNull(tag);
        Assert.assertEquals(tag.bytes().length, 3);
    }

    @Test
    public void testEqualsMixedState() {
        // A TLV with a value against one with children (value == null)

        final var t1 = TLV.of(0x9F01, hex("01")); // value != null
        final var t2 = TLV.build(0x9F01); // value == null

        Assert.assertNotEquals(t1, t2);

        // Arrays.equals(null, byte[]) -> false
        Assert.assertNotEquals(t2, t1);
    }

    @Test
    public void testInvalidBerTagMiddleByte() {
        // 9F 01 01 -> 2nd byte 01 missing 0x80 bit.
        // Should throw "Tag continuation byte missing 0x80 bit"
        final var data = hex("9F 01 01");
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(data));
    }

    @Test
    public void testEqualsSystematic() {
        // A && B && C && D
        final var t1 = TLV.of(0x9F01, hex("01"));

        // A false: instanceof
        Assert.assertNotEquals(t1, "string");

        // A true, B false: tag mismatch
        final var t2 = TLV.of(0x9F02, hex("01"));
        Assert.assertNotEquals(t1, t2);

        // A true, B true, C false: value mismatch
        final var t3 = TLV.of(0x9F01, hex("02"));
        Assert.assertNotEquals(t1, t3);

        // A true, B true, C true, D false: children mismatch
        // Need constructed TLVs for this.
        final var p1 = TLV.build(0xE0).add(t1);
        final var p2 = TLV.build(0xE0).add(t3); // t3 has diff value, so child is diff
        Assert.assertNotEquals(p1, p2);

        // All true
        final var p3 = TLV.build(0xE0).add(t1);
        Assert.assertEquals(p1, p3);
    }

    @Test
    public void testParseInvalidFourByteTag() {
        // 9F 81 81 81: the last byte still continues, with nothing following
        final var data = hex("9F 81 81 81");
        Assert.assertThrows(IllegalArgumentException.class, () -> BERTag.parse(ByteBuffer.wrap(data)));
    }

    @Test
    public void testOfNullCollection() {
        Assert.assertThrows(NullPointerException.class, () -> TLV.of(Tag.ber("E0"), (Collection<TLV>) null));
    }

    @Test
    public void testEmptyBERTag() {
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(new byte[0]));
    }

    @Test
    public void testEqualsObject() {
        final var t = TLV.build(0x9F01);
        Assert.assertNotEquals(t, new Object());
    }

    @Test
    public void testCompact() {
        // Canonical ATR objects from TS 101 220 Table 7.7: '31' Card Service Data (tag '43', 1 byte),
        // '73' Card Capabilities (tag '47', 3 bytes). Tag nibble in the high nibble, length in the low.
        final var objs = List.of(TLV.of(Tag.ber(0x43), hex("55")), TLV.of(Tag.ber(0x47), hex("A0B1C2")));
        final var compact = Compact.encode(objs);
        Assert.assertEquals(compact, hex("31 55 73 A0B1C2"));

        // Round-trip back to the canonical '4X' BER tags and values.
        final var parsed = Compact.parse(compact);
        Assert.assertEquals(parsed, TLVs.of(objs));
        Assert.assertEquals(parsed.get(0).tag(), Tag.ber(0x43));
        Assert.assertEquals(parsed.get(1).value(), hex("A0B1C2"));

        // Not narrowable: non-'4X' tag, multi-byte tag, over-long value, non-BER tag.
        Assert.expectThrows(IllegalArgumentException.class, () -> Compact.encode(List.of(TLV.of(0x80, hex("01")))));
        Assert.expectThrows(IllegalArgumentException.class, () -> Compact.encode(List.of(TLV.of(0x9F70, hex("01")))));
        Assert.expectThrows(IllegalArgumentException.class, () -> Compact.encode(List.of(TLV.of(Tag.ber(0x43), new byte[16]))));
        Assert.expectThrows(IllegalArgumentException.class, () -> Compact.encode(List.of(TLV.of(Tag.simple(0x05), hex("01")))));

        // Truncated stream: '73' promises 3 value bytes, only 1 present.
        Assert.expectThrows(TLVParseException.class, () -> Compact.parse(hex("73 A0")));
    }

    @Test
    public void testComposableParser() {
        // GPC 2.3.1 11.8.2.3.1 PUT KEY key-data-field: each key component is an opaque
        // 1-byte type + BER long-form length + value, never constructed. An RSA modulus
        // is A1 82 01 00 + 256 bytes - tag 0xA1 must NOT recurse as BER-constructed, and
        // length 82 01 00 must read as 256, not the SIMPLE 0xFF-marker form (which would
        // see 0x82 as length 130).
        final var p = TLVParser.of(Tag.Codec.SINGLE_BYTE, Len.Codec.BER, false);

        final var modulus = new byte[256];
        Arrays.fill(modulus, (byte) 0x5A);
        final var component = TLV.of(Tag.simple(0xA1), modulus);

        // Known exact vector: opaque tag A1, BER long-form length 82 01 00, 256 value bytes.
        final var encoded = p.encode(component);
        Assert.assertEquals(Arrays.copyOf(encoded, 4), hex("A1 82 01 00"));
        Assert.assertEquals(encoded.length, 4 + 256);

        // Round-trip: encode -> parse -> encode reproduces the bytes.
        final var parsed = p.parse(encoded);
        Assert.assertEquals(parsed.size(), 1);
        final var one = parsed.get(0);
        Assert.assertEquals(one.tag(), Tag.simple(0xA1));
        Assert.assertEquals(one.value().length, 256);
        Assert.assertFalse(one.isConstructed()); // 0xA1 stays primitive: no recursion
        Assert.assertEquals(p.encode(one), encoded);

        // The constructed flag alone never recurses opaque tags - they carry no constructed bit.
        Assert.assertFalse(TLVParser.of(Tag.Codec.SINGLE_BYTE, Len.Codec.BER, true)
                .parse(encoded).get(0).isConstructed());

        // BER preset: instance parse matches the TLV.parse convenience, and encode round-trips.
        final var berParser = TLVParser.of(Tag.Codec.BER, Len.Codec.BER, true);
        final var ber = hex("E0 06 9F45 03 222222");
        Assert.assertEquals(berParser.parse(ber), TLV.parse(ber));
        final var tree = TLV.of(Tag.ber(0xE0), TLV.of(0x9F45, hex("222222")));
        Assert.assertEquals(berParser.encode(tree), tree.encode());
        Assert.assertEquals(berParser.encode(tree), ber);
    }
}
