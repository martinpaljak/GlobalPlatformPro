package pro.javacard.gp;

import apdu4j.HexUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.AID;

import java.util.List;

public class TestParseTags {
    final static Logger logger = LoggerFactory.getLogger(TestParseTags.class);

    @Test
    public void testSomething() throws Exception {
        byte[] data = HexUtils.hex2bin("E3464F08A0000000030000009F700101C5039EFE80CF0140CF0141CF0142CF0143CF0180CF0181CF0182CF0183C40BD276000005AAFFCAFE0001CE020001CC08A000000003000000");
        GPRegistry reg = new GPRegistry();
        reg.parse(0x80, data, GPRegistryEntry.Kind.IssuerSecurityDomain, GlobalPlatform.GPSpec.GP22);
    }

    @Test
    public void testOther() throws Exception {
        byte[] data = HexUtils.hex2bin("664C734A06072A864886FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A864886FC6B040215650B06092B8510864864020103660C060A2B060104012A026E0102");
        GPData.pretty_print_card_data(data);
        data = HexUtils.hex2bin("6657735506072A864886FC6B01600B06092A864886FC6B020202630906072A864886FC6B03640B06092A864886FC6B040370640B06092A864886FC6B048000650A06082A864886FC6B0504660C060A2B060104012A026E0103");
        GPData.pretty_print_card_data(data);
    }

    @Test
    public void testPrintCardCapabilities() throws  Exception {
        byte[] data = HexUtils.hex2bin("6735A00E8001038106001020306070820107A007800102810215558103FF9E0082031E160083010284018F8502FF028602FF028702FF02");
        GPData.pretty_print_card_capabilities(data);

    }

    @Test
    public void testBrokenPrintCardCapabilities() throws  Exception {
        // Broken - double 0x67
        byte[] data = HexUtils.hex2bin("673A6738A006800102810155A00A8001038102001082010781039EFE8082031E03008301028504010208408602040887040102084088050102030405");
        GPData.pretty_print_card_capabilities(data);
    }



    @Test
    public void testOracle() throws Exception {
        byte[] atr = HexUtils.hex2bin("664C734A06072A864886FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A864886FC6B040215650B06092B8510864864020103660C060A2B060104012A026E0102");
        byte[] cplc = HexUtils.hex2bin("664C734A06072A864886FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A864886FC6B040215650B06092B8510864864020103660C060A2B060104012A026E0102");
        byte[] kinfo = HexUtils.hex2bin("664C734A06072A864886FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A864886FC6B040215650B06092B8510864864020103660C060A2B060104012A026E0102");

        //CardOracle.ask("https://javacard.pro/pythia", atr, cplc, kinfo, new AID("A000000151000000"));
    }

    @Test
    public void testRSAKeyTemplate() throws Exception {
        byte[] t = HexUtils.hex2bin("E020C00401018820C00402018820C00403018820C0060170A180A003C00401718010");
        List<GPKey> kl = GPData.get_key_template_list(t);
        GPData.pretty_print_key_template(kl, System.out);
    }

    @Test
    public void testExtendedRSAKeyTemplate() throws Exception {
        byte[] t = HexUtils.hex2bin("E021C00401018010C00402018010C00403018010C00D0173FFA10080A0000301840100");
        List<GPKey> kl = GPData.get_key_template_list(t);
        GPData.pretty_print_key_template(kl, System.out);
    }

    @Test
    public void testExtendedKeyTypeTemplateWithZeroLengths() throws Exception {
        byte[] t = HexUtils.hex2bin("E081B0C00A0120FF80001001000100C00A0220FF80001001000100C00A0320FF80001001000100C00A0101FF80001001000100C00A0201FF80001001000100C00A0301FF80001001000100C00A0102FF88001001000100C00E0202FF880010FF10000101000100C00A0302FF88001001000100C00A0103FF88001001000100C00E0203FF880010FF10000101000100C00A0303FF88001001000100C00A1403FF85001001000100C00A1503FF88001001000100");
        List<GPKey> kl = GPData.get_key_template_list(t);
        GPData.pretty_print_key_template(kl, System.out);
    }

    @Test
    @Ignore // FIXME: see https://github.com/martinpaljak/GlobalPlatformPro/issues/116
    public void testCPLCDateParse() throws Exception {
        byte[] b = HexUtils.hex2bin("1210");
        Assert.assertEquals("2011-07-29", GPData.CPLC.toDate(b));
        b = HexUtils.hex2bin("0000");
        Assert.assertEquals("2010-01-01", GPData.CPLC.toDate(b));
        System.out.println("Today is " + HexUtils.bin2hex(GPData.CPLC.today()));
    }

   @Test
   public void testParseISD() throws Exception {
       byte[] r = HexUtils.hex2bin("E3144F07A00000015100009F700107C50180EA028000");
       GPRegistry g = new GPRegistry();
       g.parse(0x80, r, GPRegistryEntry.Kind.IssuerSecurityDomain, GlobalPlatform.GPSpec.GP22);
       Assert.assertEquals(1, g.allAIDs().size());
       Assert.assertEquals(AID.fromString("A0000001510000"), g.getISD().getAID());
       Assert.assertEquals(1, g.getISD().getPrivileges().size());
       Assert.assertTrue(g.getISD().getPrivileges().has(GPRegistryEntry.Privilege.SecurityDomain));
       Assert.assertEquals(GPData.initializedStatus, g.getISD().getLifeCycle());
   }


    @Test(expected = GPDataException.class)
    public void testCPLCDateParseInvalid() throws Exception {
        byte[] b = HexUtils.hex2bin("1410");
        GPData.CPLC.toDate(b);
    }

    @Test(expected = GPDataException.class)
    public void testCPLCTagless() throws Exception {
        byte[] b = HexUtils.hex2bin("FF401AE218E116C1144434050D9648B771CB3500D5398D36CE3F1C23A4");
        //b = Arrays.copyOf(b, 0x2A);
        System.out.println(GPData.CPLC.fromBytes(b).toPrettyString());
    }
}
