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

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

class TestTLV {
    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replaceAll("\\s", ""));
    }

    @Test
    public void testConstruction() {
        var tlv = TLV.of("9f45", hex("01020304"));
        Assert.assertEquals(tlv.encode(), hex("9F450401020304"));
        var tlv1 = TLV.build("7f42")
                .add("9f45", hex("222222"))
                .add("9f46", hex("333333"))
                .add("9f45", hex("444444"));

        var bin = tlv1.encode();
        Assert.assertEquals(bin, hex("7F42129F45032222229F46033333339F4503444444"));

        var result = TLV.parse(bin);
        var strings = result.get(0).visualize();
        Assert.assertEquals(strings,
                List.of("[7F42]", "      [9F45] 222222", "      [9F46] 333333", "      [9F45] 444444"));

        var lookup = TLV.find(result, Tag.ber("9f45"));
        Assert.assertEquals(lookup, Optional.of(TLV.of("9f45", hex("222222"))));
        var lookup2 = TLV.findAll(result, Tag.ber("9f45"));
        Assert.assertEquals(lookup2.size(), 2);
    }

    @Test
    public void testTagFactories() {
        // Single byte tags
        var tag1 = Tag.ber(0x66);
        Assert.assertEquals(tag1.bytes(), new byte[] { 0x66 });

        // Two byte tags
        var tag2 = Tag.ber(0x9F, 0x70);
        Assert.assertEquals(tag2.bytes(), new byte[] { (byte) 0x9F, 0x70 });
    }

    @Test
    public void testAddByte() {
        var tlv = TLV.build(Tag.ber(0x70))
                .addByte(Tag.ber(0x80), (byte) 0x01)
                .addByte("81", (byte) 0xFF);

        var encoded = tlv.encode();
        Assert.assertEquals(encoded, hex("70 06 80 01 01 81 01 FF"));
    }

    @Test
    public void testParseList() {
        var data = hex("80010181010282010383010484010585010686010787010888010989010A8A010B");
        var list = TLV.parse(data);
        Assert.assertEquals(list.size(), 11);
        Assert.assertEquals(list.get(0).tag(), Tag.ber(0x80));
        Assert.assertEquals(list.get(10).tag(), Tag.ber(0x8A));
    }

    @Test
    public void testSimpleTag() {
        var tag = Tag.simple((byte) 0x01);
        Assert.assertEquals(tag.bytes(), new byte[] { 0x01 });
        Assert.assertEquals(tag.toString(), "[01]");

        // Test invalid simple tags
        Assert.assertThrows(IllegalArgumentException.class, () -> Tag.simple((byte) 0x00));
        Assert.assertThrows(IllegalArgumentException.class, () -> Tag.simple((byte) 0xFF));

        // Test construction via factories
        var tlv = TLV.of(Tag.simple((byte) 0x10), new byte[] { 0x01 });
        Assert.assertEquals(tlv.encode(), hex("10 01 01")); // Simple TLV uses 1 byte length if < 0xFF
    }

    @Test
    public void testDGITag() {
        var tag = Tag.dgi(0x1234);
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

        // Invalid multi-byte start
        // 1E is a single byte tag (bits 1-5 not all 1). So length must be 1.
        // If we pass 2 bytes, it should fail.
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(new byte[] { (byte) 0x00, (byte) 0x01 }));

        // Missing continuation bit
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(hex("9F 01 02"))); // Middle byte 01
                                                                                                // missing 0x80

        // Last byte has continuation bit
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(hex("9F 82"))); // Last byte 82 has 0x80
    }

    @Test
    public void testTLVMethods() {
        var t = TLV.build("9F45").add("81", hex("01"));

        // Children
        Assert.assertTrue(t.hasChildren());
        Assert.assertEquals(t.children().size(), 1);
        Assert.assertEquals(t.value(), t.children().get(0).encode());

        // Find
        Assert.assertNotNull(t.find(Tag.ber("81")));
        Assert.assertNull(t.find(Tag.ber("82")));

        // Find deeply
        var deep = TLV.build("7F01").add(t);
        Assert.assertNotNull(deep.find(Tag.ber("81"), 2)); // Depth sufficient
        Assert.assertNull(deep.find(Tag.ber("81"), 0)); // Depth 0 only checks root? Code: if (maxDepth >= 0 && depth >=
                                                        // maxDepth) return null

        // Check "end"
        Assert.assertEquals(t.children().get(0).end(), t);
        // t has been added to 'deep', so t.parent is deep.
        Assert.assertEquals(t.end(), deep);

        // New root TLV for exception check
        var root = TLV.build("9F45");
        Assert.assertThrows(IllegalStateException.class, () -> root.end()); // No parent

        // Add to primitive
        var p = TLV.of("81", hex("01"));
        Assert.assertThrows(IllegalStateException.class, () -> p.add("82", hex("02")));
    }

    @Test
    public void testEqualsAndHashCode() {
        var t1 = TLV.of("9F45", hex("01"));
        var t2 = TLV.of("9F45", hex("01"));
        var t3 = TLV.of("9F46", hex("01"));

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
        Assert.assertThrows(IndexOutOfBoundsException.class, () -> TLV.parse(hex("9F")));

        // Length overflow in BER
        // 84 FF FF FF FF -> 4 bytes length, code says throw if > 3 bytes (0x1000000)
        // Code: if (n > 3) throw new IllegalArgumentException("Length too large");
        Assert.assertThrows(IllegalArgumentException.class, () -> TLV.parse(hex("9F 84 FF FF FF FF")));
    }

    @Test
    public void testParseSimple() {
        // Simple TLV: Tag 01, Length 01, Value 01
        var data = hex("01 01 01");
        var list = TLVParser.parse(data, Tag.Type.SIMPLE);
        Assert.assertEquals(list.size(), 1);
        Assert.assertTrue(list.get(0).tag() instanceof SimpleTag);
        Assert.assertEquals(list.get(0).tag(), Tag.simple((byte) 0x01));
    }

    @Test
    public void testParseDGI() {
        // DGI TLV: Tag 1234, Length 01, Value 01. Length in DGI is Extended (same as
        // Simple)
        var data = hex("12 34 01 01");
        var list = TLVParser.parse(data, Tag.Type.DGI);
        Assert.assertEquals(list.size(), 1);
        Assert.assertTrue(list.get(0).tag() instanceof DGITag);
        Assert.assertEquals(list.get(0).tag(), Tag.dgi(0x1234));
    }

    @Test
    public void testUtilityConstructors() throws Exception {
        // Cover private constructors for 100% coverage
        var classes = new Class<?>[] { Len.class, TLVParser.class, TLVEncoder.class };
        for (Class<?> cls : classes) {
            var constructor = cls.getDeclaredConstructor();
            constructor.setAccessible(true);
            constructor.newInstance();
        }
    }

    @Test
    public void testLenBufferMethods() {
        // Len.ber(ByteBuffer) cases
        // 1 byte length
        Assert.assertEquals(Len.ber(java.nio.ByteBuffer.wrap(hex("7F"))), 127);
        // 2 byte length (81 80)
        Assert.assertEquals(Len.ber(java.nio.ByteBuffer.wrap(hex("81 80"))), 128);
        // 3 byte length (82 01 00)
        Assert.assertEquals(Len.ber(java.nio.ByteBuffer.wrap(hex("82 01 00"))), 256);
        // Invalid length (84 ...) -> > 3 bytes
        Assert.assertThrows(IllegalArgumentException.class,
                () -> Len.ber(java.nio.ByteBuffer.wrap(hex("84 00 00 00 00"))));

        // Len.ext(ByteBuffer) cases
        Assert.assertEquals(Len.ext(java.nio.ByteBuffer.wrap(hex("FE"))), 254);
        Assert.assertEquals(Len.ext(java.nio.ByteBuffer.wrap(hex("FF 00 FF"))), 255);
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
        var t = TLV.build("E0").add("81", hex("01")).add(TLV.build("E1").add("82", hex("02")));
        var vis = t.visualize();
        Assert.assertTrue(vis.size() > 0);
        Assert.assertTrue(vis.stream().anyMatch(s -> s.contains("[E0]")));
        Assert.assertTrue(vis.stream().anyMatch(s -> s.contains("[81]")));
        Assert.assertTrue(vis.stream().anyMatch(s -> s.contains("[E1]")));
        Assert.assertTrue(vis.stream().anyMatch(s -> s.contains("[82]")));
    }

    @Test
    public void testCoverageCompletion() {
        // TLVParser.parse(byte[], int, int, Type)
        // 00 01 01 -> we want to parse starting at index 1, length 2 (byte 01, byte 01)
        var data = hex("00 01 01 01");
        var list = TLVParser.parse(data, 1, 3, Tag.Type.SIMPLE); // Offset 1, Length 3 (01 01 01)
        Assert.assertEquals(list.size(), 1);
        Assert.assertEquals(list.get(0).tag(), Tag.simple((byte) 0x01));

        // TLV.of(Tag, Collection)
        var children = List.of(TLV.of("81", hex("01")));
        var t = TLV.of(Tag.ber("E0"), children);
        Assert.assertEquals(t.children().size(), 1);

        // TLV.find(List, Tag)
        var list2 = List.of(t);
        Assert.assertTrue(TLV.find(list2, Tag.ber("81")).isPresent());
        Assert.assertTrue(TLV.find(list2, Tag.ber("82")).isEmpty());

        // TLV.findAll(List, Tag)
        Assert.assertEquals(TLV.findAll(list2, Tag.ber("81")).size(), 1);
        Assert.assertEquals(TLV.findAll(list2, Tag.ber("82")).size(), 0);

        // TLV.add(byte[], byte[])
        var t2 = TLV.build("E0").add(hex("81"), hex("01"));
        Assert.assertTrue(t2.hasChildren());

        // Tag default methods or missing bits?
        // Maybe Tag.ber(int, int) I did cover.
        // What about Tag.Type.valueOf? (Generated enum methods)
        Assert.assertEquals(Tag.Type.valueOf("BER"), Tag.Type.BER);
        Assert.assertEquals(Tag.Type.values().length, 3);
    }

    @Test
    public void testTLVWrappers() {
        // TLV.parse(ByteBuffer)
        var data = hex("9F 45 01 01");
        var list = TLV.parse(java.nio.ByteBuffer.wrap(data));
        Assert.assertEquals(list.size(), 1);
        Assert.assertEquals(list.get(0).tag(), Tag.ber("9F45"));

        // TLV.parseSingle(ByteBuffer)
        var t = TLV.parseSingle(java.nio.ByteBuffer.wrap(data));
        Assert.assertEquals(t.tag(), Tag.ber("9F45"));

        // TLV.of(Tag, TLV...) varargs
        var child1 = TLV.of("81", hex("01"));
        var child2 = TLV.of("82", hex("02"));
        var parent = TLV.of(Tag.ber("E0"), child1, child2);
        Assert.assertEquals(parent.children().size(), 2);
    }

    @Test
    public void testPackagePrivateConstructor() {
        // Cover the package-private constructor TLV(Tag, byte[], List<TLV>)
        // which delegates to the 4-arg private one.
        var t = new TLV(Tag.ber("9F01"), hex("01"), null);
        Assert.assertEquals(t.value().length, 1);
    }

    @Test
    public void testFindAllRoot() {
        var t = TLV.of("9F45", hex("01"));
        var results = t.findAll(Tag.ber("9F45"));
        Assert.assertEquals(results.size(), 1);
        Assert.assertEquals(results.get(0), t);
    }

    @Test
    public void testEqualsDeep() {
        var t1 = TLV.of("9F45", hex("01"));
        var t2 = TLV.of("9F45", hex("02")); // Diff value
        Assert.assertNotEquals(t1, t2);

        var c1 = TLV.of(Tag.ber("E0"), t1);
        var c2 = TLV.of(Tag.ber("E0"), t2); // Diff child
        Assert.assertNotEquals(c1, c2);
    }

    @Test
    public void testOfWithNullChild() {
        java.util.List<TLV> list = new java.util.ArrayList<>();
        list.add(null);
        Assert.assertThrows(NullPointerException.class, () -> TLV.of(Tag.ber("E0"), list));
    }

    @Test
    public void testThreeByteBERTag() {
        // 9F 81 01 -> 1st byte 9F (1F, constructed), 2nd 81 (continuation), 3rd 01
        // (end)
        // This exercises the `for` loop in validate() which runs for middle bytes.
        // For a 2-byte tag like 9F 01, loop i=1; i<1 is false. Loop doesn't run.
        // For 3-byte tag, i=1; i<2. Loop runs once.
        var tag = new BERTag(hex("9F 81 01"));
        Assert.assertNotNull(tag);
        Assert.assertEquals(tag.bytes().length, 3);
    }

    @Test
    public void testEqualsMixedState() {
        // Compare TLV with value vs TLV with children (value=null)
        // using package-private constructor to force specific state if needed
        // but TLV.of(Tag, byte[]) makes value != null.
        // TLV.build(Tag) makes value == null.

        var t1 = TLV.of("9F01", hex("01")); // value != null
        var t2 = TLV.build("9F01"); // value == null

        // This hits Arrays.equals(value, other.value) -> Arrays.equals(byte[], null) ->
        // false
        Assert.assertNotEquals(t1, t2);

        // Arrays.equals(null, byte[]) -> false
        Assert.assertNotEquals(t2, t1);
    }

    @Test
    public void testInvalidBerTagMiddleByte() {
        // 9F 01 01 -> 2nd byte 01 missing 0x80 bit.
        // Should throw "Tag continuation byte missing 0x80 bit"
        var data = hex("9F 01 01");
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(data));
    }

    @Test
    public void testEqualsSystematic() {
        // A && B && C && D
        var t1 = TLV.of("9F01", hex("01"));

        // A false: instanceof
        Assert.assertNotEquals(t1, "string");

        // A true, B false: tag mismatch
        var t2 = TLV.of("9F02", hex("01"));
        Assert.assertNotEquals(t1, t2);

        // A true, B true, C false: value mismatch
        var t3 = TLV.of("9F01", hex("02"));
        Assert.assertNotEquals(t1, t3);

        // A true, B true, C true, D false: children mismatch
        // Need constructed TLVs for this.
        var p1 = TLV.build("E0").add(t1);
        var p2 = TLV.build("E0").add(t3); // t3 has diff value, so child is diff
        Assert.assertNotEquals(p1, p2);

        // All true
        var p3 = TLV.build("E0").add(t1);
        Assert.assertEquals(p1, p3);
    }

    @Test
    public void testParseInvalidFourByteTag() {
        // 9F 81 81 81.
        // Parse loop will run for i=1, i=2, i=3.
        // i=1 (81): cont.
        // i=2 (81): cont.
        // i=3 (81): cont.
        // i=4 Loop ends.
        // new BERTag called. Last byte 81 has high bit set. Throws.
        // This covers the "loop finishes without break" path in parse()
        var data = hex("9F 81 81 81");
        Assert.assertThrows(IllegalArgumentException.class, () -> BERTag.parse(java.nio.ByteBuffer.wrap(data)));
    }

    @Test
    public void testOfNullCollection() {
        Assert.assertThrows(NullPointerException.class, () -> TLV.of(Tag.ber("E0"), (java.util.Collection<TLV>) null));
    }

    @Test
    public void testEmptyBERTag() {
        Assert.assertThrows(IllegalArgumentException.class, () -> new BERTag(new byte[0]));
    }

    @Test
    public void testEqualsObject() {
        var t = TLV.build("9F01");
        Assert.assertNotEquals(t, new Object());
    }
}
