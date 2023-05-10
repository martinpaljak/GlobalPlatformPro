package pro.javacard.gp;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestKeyConverter {

    @Test
    public void testSymmetric() {
        Key k = new Key("404142434445464748494a4b4c4d4e4f");
        Assert.assertTrue(k.getSymmetric().isPresent());
        Assert.assertFalse(k.getPublic().isPresent());
        Assert.assertFalse(k.getPrivate().isPresent());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGarbage() {
        new Key("foobar");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testInvalidLength() {
        new Key("010203");
    }

    @Test
    public void testKeypair() {
        Key k = new Key("../library/src/test/resources/test-dap-rsa-1k.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertTrue(k.getPrivate().isPresent());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testBadFile() {
        Key k = new Key(".");
    }

    @Test
    public void testPrivateOnly() {
        Key k = new Key("../library/src/test/resources/test-dap-rsa-1k-priv.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertFalse(k.getPublic().isPresent());
        Assert.assertTrue(k.getPrivate().isPresent());
    }

    @Test
    public void testPublicOnly() {
        Key k = new Key("../library/src/test/resources/test-dap-rsa-1k-pub.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertFalse(k.getPrivate().isPresent());
    }
}
