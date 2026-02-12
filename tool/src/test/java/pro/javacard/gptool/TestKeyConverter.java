package pro.javacard.gptool;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestKeyConverter {

    @Test
    public void testSymmetric() {
        final Key k = Key.valueOf("404142434445464748494a4b4c4d4e4f");
        Assert.assertTrue(k.getSymmetric().isPresent());
        Assert.assertFalse(k.getPublic().isPresent());
        Assert.assertFalse(k.getPrivate().isPresent());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGarbage() {
        Key.valueOf("foobar");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testInvalidLength() {
        Key.valueOf("010203");
    }

    @Test
    public void testKeypair() {
        final Key k = Key.valueOf("../library/src/test/resources/test-dap-rsa-1k.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertTrue(k.getPrivate().isPresent());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testBadFile() {
        Key.valueOf(".");
    }

    @Test
    public void testPrivateOnly() {
        final Key k = Key.valueOf("../library/src/test/resources/test-dap-rsa-1k-priv.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertTrue(k.getPrivate().isPresent());
    }

    @Test
    public void testPublicOnly() {
        final Key k = Key.valueOf("../library/src/test/resources/test-dap-rsa-1k-pub.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertFalse(k.getPrivate().isPresent());
    }
}
