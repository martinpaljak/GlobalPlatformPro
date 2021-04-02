package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.List;

public class TestGPKeyInfo {
    static {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
    }

    @Test
    public void testRSAKeyTemplate() throws Exception {
        byte[] t = HexUtils.hex2bin("E020C00401018820C00402018820C00403018820C0060170A180A003C00401718010");
        List<GPKeyInfo> kl = GPKeyInfo.parseTemplate(t);
        System.out.println(GPKeyInfo.toString(kl));
        Assert.assertEquals(kl.size(), 5);
    }

    @Test
    public void testExtendedRSAKeyTemplate() throws Exception {
        byte[] t = HexUtils.hex2bin("E021C00401018010C00402018010C00403018010C00D0173FFA10080A0000301840100");
        List<GPKeyInfo> kl = GPKeyInfo.parseTemplate(t);
        System.out.println(GPKeyInfo.toString(kl));
        Assert.assertEquals(kl.size(), 4);
    }

    @Test
    public void testExtendedKeyTypeTemplateWithZeroLengths() throws Exception {
        byte[] t = HexUtils.hex2bin("E081B0C00A0120FF80001001000100C00A0220FF80001001000100C00A0320FF80001001000100C00A0101FF80001001000100C00A0201FF80001001000100C00A0301FF80001001000100C00A0102FF88001001000100C00E0202FF880010FF10000101000100C00A0302FF88001001000100C00A0103FF88001001000100C00E0203FF880010FF10000101000100C00A0303FF88001001000100C00A1403FF85001001000100C00A1503FF88001001000100");
        List<GPKeyInfo> kl = GPKeyInfo.parseTemplate(t);
        System.out.println(GPKeyInfo.toString(kl));
        Assert.assertEquals(kl.size(), 14);
    }
}
