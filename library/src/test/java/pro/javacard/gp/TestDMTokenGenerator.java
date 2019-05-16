package pro.javacard.gp;

import apdu4j.CommandAPDU;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;

import static pro.javacard.gp.GPSession.CLA_GP;
import static pro.javacard.gp.GPSession.INS_INSTALL;

public class TestDMTokenGenerator {

    private PrivateKey key;

    @BeforeClass
    public void setUp() throws Exception {
        try (FileInputStream fin = new FileInputStream(new File("src/test/resources/test-private.pem"))) {
            key = GPCrypto.pem2PrivateKey(fin);
        }
    }

    @Test
    public void testApplyToken() throws Exception {
        CommandAPDU command = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, new byte[]{0});
        DMTokenGenerator dmHandler = new DMTokenGenerator(key);
        command = dmHandler.applyToken(command);
        Assert.assertTrue(command.getData().length > 1); // FIXME: test for value of token content and signature
    }

    @Test
    public void testApplyEmptyToken() throws Exception {
        CommandAPDU command = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, new byte[]{0});
        DMTokenGenerator dmHandler = new DMTokenGenerator(null);
        command = dmHandler.applyToken(command);
        Assert.assertEquals(command.getData(), new byte[]{0, 0});
    }
}
