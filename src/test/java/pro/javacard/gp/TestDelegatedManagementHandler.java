package pro.javacard.gp;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;

import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;

import static pro.javacard.gp.GlobalPlatform.CLA_GP;
import static pro.javacard.gp.GlobalPlatform.INS_INSTALL;

public class TestDelegatedManagementHandler {

    private PrivateKey key;

    @Before
    public void setUp() {
        try (FileInputStream fin = new FileInputStream(new File("src/test/resources/test-private.pem"))) {
            key = GPCrypto.pem2PrivateKey(fin);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testApplyToken() {
        CommandAPDU command = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, new byte[]{0});
        DelegatedManagementHandler dmHandler = new DelegatedManagementHandler(key);
        command = dmHandler.applyToken(command);
        Assert.assertTrue(command.getData().length > 1);
    }

    @Test
    public void testApplyEmptyToken() {
        CommandAPDU command = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, new byte[]{0});
        DelegatedManagementHandler dmHandler = new DelegatedManagementHandler(null);
        command = dmHandler.applyToken(command);
        Assert.assertArrayEquals(command.getData(), new byte[]{0, 0});
    }
}
