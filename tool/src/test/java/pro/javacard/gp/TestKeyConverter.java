package pro.javacard.gp;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestKeyConverter {

    @Test
    public void testSymmetric() {
        Key k = Key.valueOf("404142434445464748494a4b4c4d4e4f");
        Assert.assertTrue(k.getSymmetric().isPresent());
        Assert.assertFalse(k.getPublic().isPresent());
        Assert.assertFalse(k.getPrivate().isPresent());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGarbage() {
        Key k = Key.valueOf("foobar");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testInvalidLength() {
        Key k = Key.valueOf("010203");
    }

    @Test
    public void testKeypair() throws Exception {
        Key k = Key.valueOf("../library/src/test/resources/test-dap-rsa-1k.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertTrue(k.getPrivate().isPresent());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testBadFile() {
        Key k = Key.valueOf(".");
    }

    @Test
    public void testPrivateOnly() {
        Key k = Key.valueOf("../library/src/test/resources/test-dap-rsa-1k-priv.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertFalse(k.getPublic().isPresent());
        Assert.assertTrue(k.getPrivate().isPresent());
    }

    @Test
    public void testPublicOnly() {
        Key k = Key.valueOf("../library/src/test/resources/test-dap-rsa-1k-pub.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertFalse(k.getPrivate().isPresent());
    }
}
