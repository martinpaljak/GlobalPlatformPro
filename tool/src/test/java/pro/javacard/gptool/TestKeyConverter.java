// SPDX-FileCopyrightText: 2021 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gptool;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.List;

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

    // EC keys as "curve:hex", and a bare uncompressed point
    @Test
    public void testEC() {
        final var point = "047E0D5C818E2B34C61247E0C58F27411C0BA782DC395B818FC5AE1F1BD9382D4BDB4CB2D4339765"
                + "0436F9C2D63668F3550877B7968370F321B07639E408AAA48D";
        for (final var spec : List.of(point, "secp256r1:" + point, "P-256:" + point)) {
            final var k = Key.valueOf(spec);
            Assert.assertTrue(k.getPublic().isPresent());
            Assert.assertFalse(k.getPrivate().isPresent());
            Assert.assertFalse(k.getSymmetric().isPresent());
        }

        // A private key comes with the public key it derives, and is never a bare value: that is a symmetric key
        final var scalar = Key.valueOf("secp256r1:C0FFEE00112233445566778899AABBCCDDEEFF00112233445566778899AABBCC");
        Assert.assertTrue(scalar.getPrivate().isPresent());
        Assert.assertTrue(scalar.getPublic().isPresent());
        Assert.assertTrue(Key.valueOf("C0FFEE00112233445566778899AABBCCDDEEFF00112233445566778899AABBCC").getSymmetric().isPresent());

        // A named curve leaves no room for the value to be anything else
        Assert.assertThrows(IllegalArgumentException.class, () -> Key.valueOf("secp256r1:0102030405"));
    }

    @Test
    public void testPublicOnly() {
        final Key k = Key.valueOf("../library/src/test/resources/test-dap-rsa-1k-pub.pem");
        Assert.assertFalse(k.getSymmetric().isPresent());
        Assert.assertTrue(k.getPublic().isPresent());
        Assert.assertFalse(k.getPrivate().isPresent());
    }
}
