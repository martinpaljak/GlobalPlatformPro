package pro.javacard.gptool;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.keys.PlaintextKeys;

import static pro.javacard.gp.GPCardKeys.KeyPurpose.*;

// Tests key parsing and derivation functionality
public class TestPlaintextKeysProvider {

    @Test
    public void testGarbage() {
        // Invalid hex should fail to parse
        try {
            HexUtils.stringToBin("404142434445464748494a4b4c4d4e4fXX");
            Assert.fail("Should have thrown exception for invalid hex");
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    @Test
    public void testMasterKey() {
        final byte[] key = HexUtils.stringToBin("404142434445464748494a4b4c4d4e4f");
        final GPCardKeys keys = PlaintextKeys.fromMasterKey(key);
        Assert.assertNotNull(keys);
    }

    @Test
    public void testDiversificationEMV() {
        final byte[] master = HexUtils.stringToBin("404142434445464748494a4b4c4d4e4f");
        GPCardKeys keys = PlaintextKeys.fromMasterKey(master, PlaintextKeys.kdf_templates.get("emv"));
        final byte[] kdd = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP02, kdd);

        Assert.assertEquals(HexUtils.hex2bin("C33013"), keys.kcv(ENC));
        Assert.assertEquals(HexUtils.hex2bin("6F4CA6"), keys.kcv(MAC));
        Assert.assertEquals(HexUtils.hex2bin("BB8179"), keys.kcv(DEK));
    }

    @Test
    public void testDiversificationVISA() {
        final byte[] master = HexUtils.stringToBin("404142434445464748494a4b4c4d4e4f");
        GPCardKeys keys = PlaintextKeys.fromMasterKey(master, PlaintextKeys.kdf_templates.get("visa2"));
        final byte[] kdd = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP02, kdd);

        Assert.assertEquals(HexUtils.hex2bin("2BE598"), keys.kcv(ENC));
        Assert.assertEquals(HexUtils.hex2bin("58DA38"), keys.kcv(MAC));
        Assert.assertEquals(HexUtils.hex2bin("3C328E"), keys.kcv(DEK));
    }

    @Test
    public void testUnknownDiversification() {
        // Unknown KDF template should return null
        final var unknownKdf = PlaintextKeys.kdf_templates.get("foobar");
        Assert.assertNull(unknownKdf);
    }

    @Test
    public void testDefaultKeys() {
        final GPCardKeys keys = PlaintextKeys.defaultKey();
        Assert.assertNotNull(keys);
    }

    @Test
    public void testDefaultKeysWithDiversifier() {
        GPCardKeys keys = PlaintextKeys.fromMasterKey(PlaintextKeys.DEFAULT_KEY(), PlaintextKeys.kdf_templates.get("kdf3"));
        final byte[] kdd = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP03, kdd);

        Assert.assertEquals(HexUtils.hex2bin("E79C05"), keys.kcv(ENC));
        Assert.assertEquals(HexUtils.hex2bin("D1BD77"), keys.kcv(MAC));
        Assert.assertEquals(HexUtils.hex2bin("3FDE8C"), keys.kcv(DEK));
    }

    @Test
    public void testKDF3() {
        final byte[] kdd = HexUtils.stringToBin("D9B1DE5D0362DEDCE4FB");
        final byte[] master = HexUtils.stringToBin("8C72C72CF908411653018807950D82FBAD947562F0828A0B10B8B9606ABF3BCD");

        System.out.println("Master: " + HexUtils.bin2hex(master));
        System.out.println("KDD: " + HexUtils.bin2hex(kdd));

        GPCardKeys ck = PlaintextKeys.fromMasterKey(master, PlaintextKeys.kdf_templates.get("kdf3"));
        ck = ck.diversify(GPSecureChannelVersion.SCP.SCP03, kdd);

        Assert.assertEquals(GPCrypto.kcv_aes(HexUtils.hex2bin("9AAC5D0B3601F89438A0D9D0B6B256CFB47E6462DFA5228D3420C4AC7C224781")), ck.kcv(ENC));
    }
}
