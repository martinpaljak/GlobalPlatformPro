package pro.javacard.gp.test;

import apdu4j.core.CommandAPDU;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import pro.javacard.gp.DMTokenizer;
import pro.javacard.gp.GPCrypto;

import java.io.FileInputStream;
import java.security.interfaces.RSAPrivateKey;

import static pro.javacard.gp.GPSession.*;

public class TestDMTokenizer {

    private RSAPrivateKey key;

    @BeforeClass
    public void setUp() throws Exception {
        try (var fin = new FileInputStream("src/test/resources/test-dm-rsa-1k.pem")) {
            key = (RSAPrivateKey) GPCrypto.pem2PrivateKey(fin);
        }
    }

    @Test
    public void testTokenizeDelete() {
        var c = new CommandAPDU(CLA_GP, INS_DELETE, 0x02, 0x00, new byte[] { 0 });
        final DMTokenizer t = DMTokenizer.forPrivateKey(key);
        c = t.tokenize(c);
        Assert.assertEquals(c.getData().length, 132);
        Assert.assertEquals(c.getData()[1] & 0xFF, 0x9E);
    }

    @Test
    public void testNullToken() {
        var c = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, new byte[] { 0 });
        final DMTokenizer t = DMTokenizer.none();
        c = t.tokenize(c);
        Assert.assertEquals(c.getData(), new byte[] { 0, 0 });
    }
}
