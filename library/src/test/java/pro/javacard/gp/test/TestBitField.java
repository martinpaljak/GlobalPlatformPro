package pro.javacard.gp.test;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.data.BitField;

import java.util.EnumSet;
import java.util.Set;

public class TestBitField {

    @Test
    public void testParsePrivileges() {
        final var v = HexUtils.hex2bin("80C000");
        final var privs = BitField.parse(Privilege.class, v, 1, 3);
        Assert.assertEquals(privs.size(), 3);
        Assert.assertTrue(privs.contains(Privilege.SecurityDomain));
        Assert.assertTrue(privs.contains(Privilege.AuthorizedManagement));
        Assert.assertTrue(privs.contains(Privilege.TrustedPath));
    }

    @Test
    public void testEncodePrivileges() {
        final var privs = EnumSet.of(Privilege.SecurityDomain, Privilege.CardLock);
        final byte[] encoded = BitField.encode(privs, 3);
        Assert.assertEquals(encoded, HexUtils.hex2bin("900000"));
    }

    @Test
    public void testRoundTrip() {
        final var v = HexUtils.hex2bin("9EFE80");
        final var privs = BitField.parse(Privilege.class, v, 1, 3);
        final byte[] encoded = BitField.encode(privs, 3);
        Assert.assertEquals(encoded, v);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testInvalidLength() {
        final var v = HexUtils.hex2bin("8000"); // 2 bytes, invalid
        BitField.parse(Privilege.class, v, 1, 3);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testRfuBitsThrow() {
        // RFU is byte_mask(2, 0x07) - all 3 bits must be set to trigger RFU match
        final var v = HexUtils.hex2bin("800007");
        BitField.parse(Privilege.class, v, 1, 3);
    }

    @Test
    public void testLaxParseNoLengthCheck() {
        // parse without length constraints (lax mode, no RFU check)
        final var v = HexUtils.hex2bin("80");
        final var privs = BitField.parse(Privilege.class, v);
        Assert.assertTrue(privs.contains(Privilege.SecurityDomain));
    }

    @Test
    public void testSignatureParse() {
        // 0x3B = 0011 1011 = bits 0,1,3,4,5
        final var v = HexUtils.hex2bin("3B");
        final var sigs = BitField.parse(GPData.SIGNATURE.class, v);
        Assert.assertEquals(sigs.size(), 5);
        Assert.assertTrue(sigs.contains(GPData.SIGNATURE.RSA1024_SHA1)); // 0x01
        Assert.assertTrue(sigs.contains(GPData.SIGNATURE.RSAPSS_SHA256)); // 0x02
        Assert.assertTrue(sigs.contains(GPData.SIGNATURE.CMAC_AES128)); // 0x08
        Assert.assertTrue(sigs.contains(GPData.SIGNATURE.CMAC_AES192)); // 0x10
        Assert.assertTrue(sigs.contains(GPData.SIGNATURE.CMAC_AES256)); // 0x20
    }

    @Test
    public void testByteMask() {
        // ByteMask matches when all bits in mask are set
        final var def = BitField.byte_mask(0, 0xC0);
        Assert.assertTrue(BitField.has(new byte[] { (byte) 0xC0 }, def, false));
        Assert.assertTrue(BitField.has(new byte[] { (byte) 0xFF }, def, false));
        Assert.assertFalse(BitField.has(new byte[] { (byte) 0x80 }, def, false));
    }

    @Test
    public void testSingleByte() {
        final byte[] v = new byte[] { (byte) 0x80 };
        final var privs = BitField.parse(Privilege.class, v, 1, 3);
        Assert.assertTrue(privs.contains(Privilege.SecurityDomain));
    }

    @Test
    public void testByteLength() {
        Assert.assertEquals(BitField.length(Privilege.class), 3);

        // Test with simpler Enum
        Assert.assertEquals(BitField.length(GPData.SIGNATURE.class), 2);
    }
}
