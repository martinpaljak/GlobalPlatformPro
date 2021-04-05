package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

import static pro.javacard.gp.GPCardKeys.KeyPurpose.ENC;
import static pro.javacard.gp.PlaintextKeys.SCP03_KDF_CONSTANTS;

public class TestSCP03 {

    @Test
    public void testKDF3() {
        byte[] kdd = HexUtils.stringToBin("D9B1DE5D0362DEDCE4FB");
        byte[] master = HexUtils.stringToBin("8C72C72CF908411653018807950D82FBAD947562F0828A0B10B8B9606ABF3BCD");

        System.out.println("Master: " + HexUtils.bin2hex(master));
        System.out.println("KDD: " + HexUtils.bin2hex(kdd));

        byte[] blocka = new byte[]{};
        byte[] blockb = GPUtils.concatenate(SCP03_KDF_CONSTANTS.get(ENC), kdd);

        final byte[] kv = GPCrypto.scp03_kdf(master, blocka, blockb, master.length);
        System.out.println("ENC: " + HexUtils.bin2hex(kv));
        Assert.assertEquals(HexUtils.hex2bin("9AAC5D0B3601F89438A0D9D0B6B256CFB47E6462DFA5228D3420C4AC7C224781"), kv);
    }
}
