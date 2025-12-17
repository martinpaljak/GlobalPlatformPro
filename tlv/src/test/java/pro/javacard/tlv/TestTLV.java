package pro.javacard.tlv;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

public class TestTLV {
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
        Assert.assertEquals(strings, List.of("[7F42]", "      [9F45] 222222", "      [9F46] 333333", "      [9F45] 444444"));

        var lookup = TLV.find(result, Tag.ber("9f45"));
        Assert.assertEquals(lookup, Optional.of(TLV.of("9f45", hex("222222"))));
        var lookup2 = TLV.findAll(result, Tag.ber("9f45"));
        Assert.assertEquals(lookup2.size(), 2);
    }

    @Test
    public void testTagFactories() {
        // Single byte tags
        var tag1 = Tag.ber(0x66);
        Assert.assertEquals(tag1.bytes(), new byte[]{0x66});

        // Two byte tags
        var tag2 = Tag.ber(0x9F, 0x70);
        Assert.assertEquals(tag2.bytes(), new byte[]{(byte) 0x9F, 0x70});
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
}
