package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.AID;
import pro.javacard.gp.GPData.CPLC;
import pro.javacard.gp.GPRegistryEntry.Privilege;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class TestParseTags {
    static {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
    }

    final static Logger logger = LoggerFactory.getLogger(TestParseTags.class);

    @Test
    public void testParsePartialISD() throws Exception {
        byte[] data = HexUtils.hex2bin("E3464F08A0000000030000009F700101C5039EFE80CF0140CF0141CF0142CF0143CF0180CF0181CF0182CF0183C40BD276000005AAFFCAFE0001CE020001CC08A000000003000000");
        GPRegistry reg = new GPRegistry();
        reg.parse_and_populate(0x80, data, GPRegistryEntry.Kind.IssuerSecurityDomain, GPCardProfile.defaultProfile());
        GPCommands.listRegistry(reg, System.out, true);
    }

    @Test
    public void testOther() throws Exception {
        byte[] data = HexUtils.hex2bin("664C734A06072A864886FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A864886FC6B040215650B06092B8510864864020103660C060A2B060104012A026E0102");
        GPData.pretty_print_card_data(data);
        data = HexUtils.hex2bin("6657735506072A864886FC6B01600B06092A864886FC6B020202630906072A864886FC6B03640B06092A864886FC6B040370640B06092A864886FC6B048000650A06082A864886FC6B0504660C060A2B060104012A026E0103");
        GPData.pretty_print_card_data(data);
    }

    @Test
    public void testPrintCardCapabilities() throws Exception {
        byte[] data = HexUtils.hex2bin("6735A00E8001038106001020306070820107A007800102810215558103FF9E0082031E160083010284018F8502FF028602FF028702FF02");
        GPData.pretty_print_card_capabilities(data);
    }

    @Test
    public void testBrokenPrintCardCapabilities() throws Exception {
        // Broken - double 0x67
        byte[] data = HexUtils.hex2bin("673A6738A006800102810155A00A8001038102001082010781039EFE8082031E03008301028504010208408602040887040102084088050102030405");
        GPData.pretty_print_card_capabilities(data);
    }

    @Test
    public void testCPLCDateParse() throws Exception {
        // Day 210 of year 20?1
        byte[] b = HexUtils.hex2bin("1210");
        Assert.assertEquals(Optional.of(LocalDate.of(2021, 07, 29)), CPLC.toRelativeDate(b, LocalDate.of(2021, 07, 30)));
        // For dates recorded on the same day, we want the reverse to show the right date
        Assert.assertEquals(Optional.of(LocalDate.of(2021, 07, 29)), CPLC.toRelativeDate(b, LocalDate.of(2021, 07, 29)));
        Assert.assertEquals(Optional.of(LocalDate.of(2011, 07, 29)), CPLC.toRelativeDate(b, LocalDate.of(2021, 07, 28)));

        b = HexUtils.hex2bin("0000");
        Assert.assertTrue(CPLC.toRelativeDate(b, LocalDate.now()).isEmpty());

        LocalDate now = LocalDate.now();
        Assert.assertEquals(CPLC.toRelativeDate(CPLC.dateToBytes(now), now), Optional.of(now));
        byte[] today = CPLC.dateToBytes(now);
        System.out.printf("Today is %s what is %s%n", HexUtils.bin2hex(today), CPLC.toRelativeDate(today, now));
    }

    @Test
    public void testParseISD() throws Exception {
        byte[] r = HexUtils.hex2bin("E3144F07A00000015100009F700107C50180EA028000");
        GPRegistry g = new GPRegistry();
        g.parse_and_populate(0x80, r, GPRegistryEntry.Kind.IssuerSecurityDomain, GPCardProfile.defaultProfile());
        GPRegistryEntry isd = g.getISD().orElseThrow(() -> new Exception("No ISD"));
        Assert.assertEquals(1, g.allAIDs().size());
        Assert.assertEquals(AID.fromString("A0000001510000"), isd.getAID());
        Assert.assertEquals(1, isd.getPrivileges().size());
        Assert.assertTrue(isd.hasPrivilege(Privilege.SecurityDomain));
        Assert.assertEquals(GPData.initializedStatus, isd.getLifeCycle());
    }


    @Test
    public void testCPLCDateParseInvalid() throws Exception {
        byte[] b = HexUtils.hex2bin("1410");
        Assert.assertEquals(CPLC.toRelativeDate(b, LocalDate.now()), Optional.empty());
    }

    @Test(expectedExceptions = GPDataException.class)
    public void testCPLCTagless() throws Exception {
        byte[] b = HexUtils.hex2bin("FF401AE218E116C1144434050D9648B771CB3500D5398D36CE3F1C23A4");
        //b = Arrays.copyOf(b, 0x2A);
        System.out.println(CPLC.fromBytes(b).toPrettyString());
    }

    @Test
    public void testCardCapabilities() {
        byte[] v = HexUtils.hex2bin("3B");
        Set<GPData.SIGNATURE> ciphers = GPData.SIGNATURE.byValue(v);
        Assert.assertEquals(ciphers.size(), 5);
        System.out.println(ciphers);
    }

    @Test
    public void testLFDBH() {
        byte[] v = HexUtils.hex2bin("0102");
        List<GPData.LFDBH> hashes = GPData.LFDBH.fromBytes(v);
        Assert.assertEquals(hashes.size(), 2);
        System.out.println(hashes);
    }

    @Test
    public void testPrivileges() {
        byte[] v = HexUtils.hex2bin("80C000");
        Set<Privilege> privileges = Privilege.fromBytes(v);
        Assert.assertEquals(privileges.size(), 3);
        Assert.assertTrue(privileges.contains(Privilege.AuthorizedManagement));
        Assert.assertTrue(privileges.contains(Privilege.SecurityDomain));
        Assert.assertTrue(privileges.contains(Privilege.TrustedPath));
        Assert.assertEquals(Privilege.toBytes(privileges), v);

        v = HexUtils.hex2bin("9EFE80");
        privileges = Privilege.fromBytes(v);
        Assert.assertEquals(privileges.size(), 13);
        Assert.assertEquals(Privilege.toBytes(privileges), v);
    }

    @Test
    public void testLV() {
        byte[] data = Hex.decode("05060906090608D233000000444F4D20DADFAD3ABBEFC249B1C878566C24ECB072289A15D06F4539E4AF03E876F763F0 00 81804861F702FE0C7E2FDA2F993A19C93F6326A4AE5E0DA72500E4754F7C1A82DA07554D2E084799AFA7037A25CF9E2A7EA67066C4FDCC0DC2C5FD096BA4BEB3C7A4462E040A3F8AC9FF870DA2A4CF624466A43BE8D75713F3D4A7263A1A4C1B6E819FE73A80B46E4F03C20A6FBE44B55A036923D2F9C3090CA3EA2E463B83A13DB7");
        GPUtils.trace_lv(data, logger);
    }
}
