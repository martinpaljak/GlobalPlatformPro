package pro.javacard.gp.test;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.GPKeyInfo;

import java.util.List;

public class TestGPKeyInfo {
    static {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
    }

    @Test
    public void testRSAKeyTemplate() throws Exception {
        final var t = HexUtils.hex2bin("E020C00401018820C00402018820C00403018820C0060170A180A003C00401718010");
        final var kl = GPKeyInfo.parseTemplate(t);
        System.out.println(GPKeyInfo.toString(kl));
        Assert.assertEquals(kl.size(), 5);
    }

    @Test
    public void testExtendedRSAKeyTemplate() throws Exception {
        final var t = HexUtils.hex2bin("E021C00401018010C00402018010C00403018010C00D0173FFA10080A0000301840100");
        final var kl = GPKeyInfo.parseTemplate(t);
        System.out.println(GPKeyInfo.toString(kl));
        Assert.assertEquals(kl.size(), 4);
    }

    @Test
    public void testSCP11KeyTemplate() throws Exception {
        // SCP03 (version 0x31) + SCP11 (version 0x18) key template from real card
        final var t = HexUtils.hex2bin(
                "E047C00401318810C00402318810C00403318810C0101018B041B220B320B420B541B620B702C0211518FFB10020FFB20020FFB30020FFB40020FFB50041FFB60020FFB70002000100");
        final var kl = GPKeyInfo.parseTemplate(t);
        final var output = GPKeyInfo.toString(kl);
        System.out.println(output);
        Assert.assertEquals(kl.size(), 5);
        // SCP11 key descriptions
        Assert.assertTrue(output.contains("P-256 public"), "Should contain P-256 public");
        Assert.assertTrue(output.contains("P-256 private"), "Should contain P-256 private");
        Assert.assertTrue(output.contains("SCP11 CA Verification"), "Should contain SCP11 CA Verification for ID 0x10");
        Assert.assertTrue(output.contains("SCP11c Key Agreement"), "Should contain SCP11c Key Agreement for ID 0x15");
    }

    @Test
    public void testExtendedKeyTypeTemplateWithZeroLengths() throws Exception {
        final var t = HexUtils.hex2bin(
                "E081B0C00A0120FF80001001000100C00A0220FF80001001000100C00A0320FF80001001000100C00A0101FF80001001000100C00A0201FF80001001000100C00A0301FF80001001000100C00A0102FF88001001000100C00E0202FF880010FF10000101000100C00A0302FF88001001000100C00A0103FF88001001000100C00E0203FF880010FF10000101000100C00A0303FF88001001000100C00A1403FF85001001000100C00A1503FF88001001000100");
        final var kl = GPKeyInfo.parseTemplate(t);
        System.out.println(GPKeyInfo.toString(kl));
        Assert.assertEquals(kl.size(), 14);
    }
}
