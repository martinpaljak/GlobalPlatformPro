package pro.javacard.gptool;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.CardKeysProvider;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gptool.keys.PlaintextKeys;

import java.util.Optional;

import static pro.javacard.gp.GPCardKeys.KeyPurpose.*;

public class TestPlaintextKeysProvider {

    @Test
    public void testGarbage() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Assert.assertFalse(p.getCardKeys("404142434445464748494a4b4c4d4e4fXX").isPresent());
    }

    @Test
    public void testMasterKey() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Assert.assertTrue(p.getCardKeys("404142434445464748494a4b4c4d4e4f").isPresent());
    }

    @Test
    public void testDiversificationEMV() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Optional<GPCardKeys> pk = p.getCardKeys("emv:404142434445464748494a4b4c4d4e4f");
        Assert.assertTrue(pk.isPresent());
        GPCardKeys keys = pk.get();
        byte[] kdd = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP02, kdd);

        Assert.assertEquals(HexUtils.hex2bin("C33013"), keys.kcv(ENC));
        Assert.assertEquals(HexUtils.hex2bin("6F4CA6"), keys.kcv(MAC));
        Assert.assertEquals(HexUtils.hex2bin("BB8179"), keys.kcv(DEK));
    }

    @Test
    public void testDiversificationVISA() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Optional<GPCardKeys> pk = p.getCardKeys("visa2:404142434445464748494a4b4c4d4e4f");
        Assert.assertTrue(pk.isPresent());
        GPCardKeys keys = pk.get();
        byte[] kdd = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP02, kdd);


        Assert.assertEquals(HexUtils.hex2bin("2BE598"), keys.kcv(ENC));
        Assert.assertEquals(HexUtils.hex2bin("58DA38"), keys.kcv(MAC));
        Assert.assertEquals(HexUtils.hex2bin("3C328E"), keys.kcv(DEK));
    }

    @Test
    public void testUnknownDiversification() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Optional<GPCardKeys> pk = p.getCardKeys("foobar:404142434445464748494a4b4c4d4e4f");
        Assert.assertFalse(pk.isPresent());
    }

    @Test
    public void testDefaultKeys() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Optional<GPCardKeys> pk = p.getCardKeys("default");
        Assert.assertTrue(pk.isPresent());
    }

    @Test
    public void testDefaultKeysWithDiversifier() throws Exception {
        CardKeysProvider p = new PlaintextKeysProvider();
        Optional<GPCardKeys> pk = p.getCardKeys("kdf3:default");
        Assert.assertTrue(pk.isPresent());
        GPCardKeys keys = pk.get();
        byte[] kdd = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP03, kdd);

        Assert.assertEquals(HexUtils.hex2bin("E79C05"), keys.kcv(ENC));
        Assert.assertEquals(HexUtils.hex2bin("D1BD77"), keys.kcv(MAC));
        Assert.assertEquals(HexUtils.hex2bin("3FDE8C"), keys.kcv(DEK));
    }

    @Test
    public void testKDF3() {
        byte[] kdd = HexUtils.stringToBin("D9B1DE5D0362DEDCE4FB");
        byte[] master = HexUtils.stringToBin("8C72C72CF908411653018807950D82FBAD947562F0828A0B10B8B9606ABF3BCD");

        System.out.println("Master: " + HexUtils.bin2hex(master));
        System.out.println("KDD: " + HexUtils.bin2hex(kdd));

        GPCardKeys ck = PlaintextKeys.fromMasterKey(master, PlaintextKeys.kdf_templates.get("kdf3"));
        ck = ck.diversify(GPSecureChannelVersion.SCP.SCP03, kdd);

        Assert.assertEquals(GPCrypto.kcv_aes(HexUtils.hex2bin("9AAC5D0B3601F89438A0D9D0B6B256CFB47E6462DFA5228D3420C4AC7C224781")), ck.kcv(ENC));
    }
}
