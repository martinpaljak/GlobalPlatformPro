package pro.javacard.gp;

import apdu4j.core.CommandAPDU;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.security.interfaces.RSAPrivateKey;

import static pro.javacard.gp.GPSession.*;

public class TestDMTokenizer {

    private RSAPrivateKey key;

    @BeforeClass
    public void setUp() throws Exception {
        try (FileInputStream fin = new FileInputStream("src/test/resources/test-dm-rsa-1k.pem")) {
            key = (RSAPrivateKey) GPCrypto.pem2PrivateKey(fin);
        }
    }

    @Test
    public void testTokenizeDelete() {
        CommandAPDU c = new CommandAPDU(CLA_GP, INS_DELETE, 0x02, 0x00, new byte[]{0});
        DMTokenizer t = DMTokenizer.forPrivateKey(key);
        c = t.tokenize(c);
        Assert.assertEquals(c.getData().length, 132);
        Assert.assertEquals(c.getData()[1] & 0xFF, 0x9E);
    }

    @Test
    public void testNullToken() {
        CommandAPDU c = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, new byte[]{0});
        DMTokenizer t = DMTokenizer.none();
        c = t.tokenize(c);
        Assert.assertEquals(c.getData(), new byte[]{0, 0});
    }
}
