// SPDX-FileCopyrightText: 2021 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestPlaintextKey {

    @Test
    public void testSymmetric() {
        var k = PlaintextKey.valueOf("404142434445464748494a4b4c4d4e4f");
        Assert.assertTrue(k.getSymmetric().isPresent());
        Assert.assertFalse(k.getPublic().isPresent());
        Assert.assertFalse(k.getPrivate().isPresent());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGarbage() {
        PlaintextKey.valueOf("foobar");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testInvalidLength() {
        PlaintextKey.valueOf("010203");
    }

    @Test
    public void testKeypair() {
        var k = PlaintextKey.valueOf("../library/src/test/resources/test-dap-rsa-1k.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertTrue(k.getPrivate().isPresent());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testBadFile() {
        PlaintextKey.valueOf(".");
    }

    @Test
    public void testPrivateOnly() {
        var k = PlaintextKey.valueOf("../library/src/test/resources/test-dap-rsa-1k-priv.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertTrue(k.getPrivate().isPresent());
    }

    @Test
    public void testPublicOnly() {
        var k = PlaintextKey.valueOf("../library/src/test/resources/test-dap-rsa-1k-pub.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertFalse(k.getPrivate().isPresent());
    }

    @Test
    public void testAesPrefix() {
        var k = PlaintextKey.valueOf("aes:404142434445464748494a4b4c4d4e4f");
        Assert.assertTrue(k.getSymmetric().isPresent());
    }

    @Test
    public void test3desPrefix() {
        var k = PlaintextKey.valueOf("3des:404142434445464748494a4b4c4d4e4f");
        Assert.assertTrue(k.getSymmetric().isPresent());
    }
}
