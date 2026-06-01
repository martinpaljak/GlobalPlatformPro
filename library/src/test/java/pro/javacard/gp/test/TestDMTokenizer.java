// SPDX-FileCopyrightText: 2020 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.test;

import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import pro.javacard.gp.DMTokenizer;
import pro.javacard.gp.GPCrypto;

import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;

import static pro.javacard.gp.GPSession.*;

public class TestDMTokenizer {

    private RSAPrivateKey key;

    @BeforeClass
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
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
    public void testAESTokenizeInstall() {
        // AES-128 key
        final var aesKey = new SecretKeySpec(HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F"), "AES");
        var c = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, new byte[] { 0 });
        final DMTokenizer t = DMTokenizer.forAESKey(aesKey);
        c = t.tokenize(c);
        // 1 byte original data + 1 byte token length + 16 byte CMAC = 18
        Assert.assertEquals(c.getData().length, 18);
        // Token length should be 16 (full AES CMAC per GP 2.3.1 C.4)
        Assert.assertEquals(c.getData()[1] & 0xFF, 16);
    }

    @Test
    public void testAESTokenizeDelete() {
        final var aesKey = new SecretKeySpec(HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F"), "AES");
        var c = new CommandAPDU(CLA_GP, INS_DELETE, 0x02, 0x00, new byte[] { 0 });
        final DMTokenizer t = DMTokenizer.forAESKey(aesKey);
        c = t.tokenize(c);
        // 1 byte original data + tag 0x9E + 1 byte length + 16 byte CMAC = 19
        Assert.assertEquals(c.getData().length, 19);
        Assert.assertEquals(c.getData()[1] & 0xFF, 0x9E);
        Assert.assertEquals(c.getData()[2] & 0xFF, 16);
    }

    @Test
    public void testAESTokenDeterministic() {
        // Same key and APDU should produce the same token
        final var aesKey = new SecretKeySpec(HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F"), "AES");
        final var apdu = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, new byte[] { 0 });
        final var t1 = DMTokenizer.forAESKey(aesKey);
        final var t2 = DMTokenizer.forAESKey(aesKey);
        final var c1 = t1.tokenize(apdu);
        final var c2 = t2.tokenize(apdu);
        Assert.assertEquals(c1.getData(), c2.getData());
    }

    @Test
    public void testAESCmacRoundtrip() throws Exception {
        final var keyBytes = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");
        final var key = new SecretKeySpec(keyBytes, "AES");
        final var data = HexUtils.hex2bin("0102030405060708");
        final byte[] fromBytes = GPCrypto.aes_cmac(keyBytes, data, 128);
        final byte[] fromKey = GPCrypto.aes_cmac(key, data, 128);
        Assert.assertEquals(fromKey, fromBytes);
    }

    @Test
    public void testNullToken() {
        var c = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, new byte[] { 0 });
        final DMTokenizer t = DMTokenizer.none();
        c = t.tokenize(c);
        Assert.assertEquals(c.getData(), new byte[] { 0, 0 });
    }
}
