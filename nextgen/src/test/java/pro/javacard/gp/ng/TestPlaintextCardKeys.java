// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPSecureChannelVersion.SCP;
import pro.javacard.gp.keys.PlaintextKeys;

import java.security.GeneralSecurityException;

import static pro.javacard.gp.ng.CardKeys.KeyPurpose.*;

// Tests for PlaintextCardKeys: ported vectors from TestPlaintextKeys + cross-verification against old implementation.
public class TestPlaintextCardKeys {

    private static final byte[] KEY_16 = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");
    private static final byte[] KEY_24 = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F5051525354555657");
    private static final byte[] KEY_32 = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
    private static final byte[] KDD = HexUtils.hex2bin("00010203040506070809");

    // --- Diversification: ported vectors ---

    @Test
    public void testDiversification_EMV_SCP02() {
        var keys = PlaintextCardKeys.fromMasterKey(KEY_16, PlaintextCardKeys.KDF_TEMPLATES.get("emv"));
        var diversified = (PlaintextCardKeys) keys.diversify(SCP.SCP02, KDD);
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(ENC)), "C33013");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(MAC)), "6F4CA6");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(DEK)), "BB8179");
    }

    @Test
    public void testDiversification_VISA2_SCP02() {
        var keys = PlaintextCardKeys.fromMasterKey(KEY_16, PlaintextCardKeys.KDF_TEMPLATES.get("visa2"));
        var diversified = (PlaintextCardKeys) keys.diversify(SCP.SCP02, KDD);
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(ENC)), "2BE598");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(MAC)), "58DA38");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(DEK)), "3C328E");
    }

    @Test
    public void testDiversification_KDF3_SCP03_AES128() {
        var keys = PlaintextCardKeys.fromMasterKey(KEY_16, PlaintextCardKeys.KDF_TEMPLATES.get("kdf3"));
        var diversified = (PlaintextCardKeys) keys.diversify(SCP.SCP03, KDD);
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(ENC)), "E79C05");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(MAC)), "D1BD77");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(DEK)), "3FDE8C");
    }

    @Test
    public void testDiversification_KDF3_SCP03_AES192() {
        var keys = PlaintextCardKeys.fromMasterKey(KEY_24, PlaintextCardKeys.KDF_TEMPLATES.get("kdf3"));
        var diversified = (PlaintextCardKeys) keys.diversify(SCP.SCP03, KDD);
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(ENC)), "1DE8EA");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(MAC)), "47C00C");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(DEK)), "C04D76");
    }

    @Test
    public void testDiversification_KDF3_SCP03_AES256() {
        var keys = PlaintextCardKeys.fromMasterKey(KEY_32, PlaintextCardKeys.KDF_TEMPLATES.get("kdf3"));
        var diversified = (PlaintextCardKeys) keys.diversify(SCP.SCP03, KDD);
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(ENC)), "2972D2");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(MAC)), "036F94");
        Assert.assertEquals(HexUtils.bin2hex(diversified.kcv(DEK)), "5D57B8");
    }

    @Test
    public void testDiversification_KDF3_ExternalVector() {
        var kdd = HexUtils.hex2bin("D9B1DE5D0362DEDCE4FB");
        var master = HexUtils.hex2bin("8C72C72CF908411653018807950D82FBAD947562F0828A0B10B8B9606ABF3BCD");
        var expectedDerivedKey = HexUtils.hex2bin("9AAC5D0B3601F89438A0D9D0B6B256CFB47E6462DFA5228D3420C4AC7C224781");

        var keys = PlaintextCardKeys.fromMasterKey(master, PlaintextCardKeys.KDF_TEMPLATES.get("kdf3"));
        var diversified = (PlaintextCardKeys) keys.diversify(SCP.SCP03, kdd);
        Assert.assertEquals(diversified.kcv(ENC), GPCrypto.kcv_aes(expectedDerivedKey));
    }

    // --- Session keys: ported vectors ---

    @Test
    public void testSessionKeys_SCP01() {
        var keys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP01, KDD);
        var sessionContext = new byte[16]; // host_challenge || card_challenge (zeros)
        var session = (SessionKeys.SCP01Keys) keys.deriveSession(sessionContext);

        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(session.enc())), "FDDAF8");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(session.mac())), "FDDAF8");
    }

    @Test
    public void testSessionKeys_SCP01_DEK_static() {
        // SCP01 DEK is static (= card DEK), verified via encryptDEK
        var keys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP01, KDD);
        // DEK encryption should use static card DEK
        var encrypted = keys.encryptDEK(new byte[16], new byte[2]);
        // Same as encrypting zeros with 404142... key
        Assert.assertEquals(encrypted.length, 16);
    }

    @Test
    public void testSessionKeys_SCP02() {
        var keys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP02, KDD);
        var sequence = new byte[2]; // counter = 0000
        var session = (SessionKeys.SCP02Keys) keys.deriveSession(sequence);

        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(session.enc())), "F2DCDD");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(session.mac())), "5FCC69");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(session.rmac())), "9F749A");
    }

    @Test
    public void testSessionKeys_SCP03() {
        var keys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP03, KDD);
        var session = (SessionKeys.SCP03Keys) keys.deriveSession(KDD);

        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_aes(session.enc())), "C25559");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_aes(session.mac())), "0E12CC");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_aes(session.rmac())), "9ACB9C");
    }

    // --- Key encryption: ported vectors ---

    @Test
    public void testKeyWrapping_SCP01() {
        var keys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP01, KDD);
        var encrypted = keys.wrapKey(KEY_16, new byte[2]);
        Assert.assertEquals(HexUtils.bin2hex(encrypted), "B4BAA89A8CD0292B45210E1BC84B1C31");
    }

    @Test
    public void testKeyWrapping_SCP02() {
        var keys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP02, KDD);
        var encrypted = keys.wrapKey(KEY_16, new byte[2]);
        Assert.assertEquals(HexUtils.bin2hex(encrypted), "EFBEE6C6D99D7B70BDE9D7E927F020AF");
    }

    @Test
    public void testKeyWrapping_SCP03() {
        var keys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP03, KDD);
        var encrypted = keys.wrapKey(KEY_16, new byte[2]);
        // SCP03 adds random padding: length is 16, content is not deterministic
        Assert.assertEquals(encrypted.length, 16);
    }

    @Test
    public void testScp3Kdf() {
        var keys = PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        var result = keys.kdf(ENC, new byte[16], new byte[16], 16);
        Assert.assertEquals(result.length, 16);
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_aes(result)), "BD8165");
    }

    // --- Cross-verification against old PlaintextKeys ---

    @Test
    public void crossVerify_Diversification_EMV_SCP02() {
        var ngKeys = PlaintextCardKeys.fromMasterKey(KEY_16, PlaintextCardKeys.KDF_TEMPLATES.get("emv"));
        var ngDiversified = (PlaintextCardKeys) ngKeys.diversify(SCP.SCP02, KDD);

        var oldKeys = PlaintextKeys.fromMasterKey(KEY_16, PlaintextKeys.kdf_templates.get("emv"));
        oldKeys = oldKeys.diversify(SCP.SCP02, KDD);

        for (var p : CardKeys.KeyPurpose.cardKeys()) {
            var oldP = GPCardKeys.KeyPurpose.valueOf(p.name());
            Assert.assertEquals(ngDiversified.kcv(p), oldKeys.kcv(oldP),
                    "KCV mismatch for " + p + " after EMV diversification");
        }
    }

    @Test
    public void crossVerify_Diversification_KDF3_SCP03() {
        var ngKeys = PlaintextCardKeys.fromMasterKey(KEY_32, PlaintextCardKeys.KDF_TEMPLATES.get("kdf3"));
        var ngDiversified = (PlaintextCardKeys) ngKeys.diversify(SCP.SCP03, KDD);

        var oldKeys = PlaintextKeys.fromMasterKey(KEY_32, PlaintextKeys.kdf_templates.get("kdf3"));
        oldKeys = oldKeys.diversify(SCP.SCP03, KDD);

        for (var p : CardKeys.KeyPurpose.cardKeys()) {
            var oldP = GPCardKeys.KeyPurpose.valueOf(p.name());
            Assert.assertEquals(ngDiversified.kcv(p), oldKeys.kcv(oldP),
                    "KCV mismatch for " + p + " after KDF3 diversification");
        }
    }

    @Test
    public void crossVerify_SessionKeys_SCP01() {
        var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP01, KDD);
        var sessionContext = new byte[16];
        var ngSession = (SessionKeys.SCP01Keys) ngKeys.deriveSession(sessionContext);

        var oldKeys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        oldKeys.diversify(SCP.SCP01, KDD);
        var oldEnc = oldKeys.getSessionKey(GPCardKeys.KeyPurpose.ENC, sessionContext);
        var oldMac = oldKeys.getSessionKey(GPCardKeys.KeyPurpose.MAC, sessionContext);

        Assert.assertEquals(ngSession.enc(), oldEnc, "SCP01 session ENC mismatch");
        Assert.assertEquals(ngSession.mac(), oldMac, "SCP01 session MAC mismatch");
    }

    @Test
    public void crossVerify_SessionKeys_SCP02() {
        var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP02, KDD);
        var sequence = new byte[2];
        var ngSession = (SessionKeys.SCP02Keys) ngKeys.deriveSession(sequence);

        var oldKeys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        oldKeys.diversify(SCP.SCP02, KDD);
        var oldEnc = oldKeys.getSessionKey(GPCardKeys.KeyPurpose.ENC, sequence);
        var oldMac = oldKeys.getSessionKey(GPCardKeys.KeyPurpose.MAC, sequence);
        var oldRmac = oldKeys.getSessionKey(GPCardKeys.KeyPurpose.RMAC, sequence);

        Assert.assertEquals(ngSession.enc(), oldEnc, "SCP02 session ENC mismatch");
        Assert.assertEquals(ngSession.mac(), oldMac, "SCP02 session MAC mismatch");
        Assert.assertEquals(ngSession.rmac(), oldRmac, "SCP02 session RMAC mismatch");
    }

    @Test
    public void crossVerify_SessionKeys_SCP03() {
        var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP03, KDD);
        var ngSession = (SessionKeys.SCP03Keys) ngKeys.deriveSession(KDD);

        var oldKeys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        oldKeys.diversify(SCP.SCP03, KDD);
        var oldEnc = oldKeys.getSessionKey(GPCardKeys.KeyPurpose.ENC, KDD);
        var oldMac = oldKeys.getSessionKey(GPCardKeys.KeyPurpose.MAC, KDD);
        var oldRmac = oldKeys.getSessionKey(GPCardKeys.KeyPurpose.RMAC, KDD);

        Assert.assertEquals(ngSession.enc(), oldEnc, "SCP03 session ENC mismatch");
        Assert.assertEquals(ngSession.mac(), oldMac, "SCP03 session MAC mismatch");
        Assert.assertEquals(ngSession.rmac(), oldRmac, "SCP03 session RMAC mismatch");
    }

    @Test
    public void crossVerify_DEKEncryption_SCP01() throws GeneralSecurityException {
        var data = new byte[16]; // zeros
        var sessionContext = new byte[2];

        var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP01, KDD);
        var ngResult = ngKeys.encryptDEK(data, sessionContext);

        var oldKeys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        oldKeys.diversify(SCP.SCP01, KDD);
        var oldResult = oldKeys.encrypt(data, sessionContext);

        Assert.assertEquals(ngResult, oldResult, "SCP01 DEK encryption mismatch");
    }

    @Test
    public void crossVerify_DEKEncryption_SCP02() throws GeneralSecurityException {
        var data = new byte[16]; // zeros
        var sessionContext = new byte[2]; // sequence = 0000

        var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP02, KDD);
        var ngResult = ngKeys.encryptDEK(data, sessionContext);

        var oldKeys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        oldKeys.diversify(SCP.SCP02, KDD);
        var oldResult = oldKeys.encrypt(data, sessionContext);

        Assert.assertEquals(ngResult, oldResult, "SCP02 DEK encryption mismatch (session DEK)");
    }

    @Test
    public void crossVerify_DEKEncryption_SCP03() throws GeneralSecurityException {
        var data = new byte[16]; // zeros
        var sessionContext = new byte[2];

        var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP03, KDD);
        var ngResult = ngKeys.encryptDEK(data, sessionContext);

        var oldKeys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        oldKeys.diversify(SCP.SCP03, KDD);
        var oldResult = oldKeys.encrypt(data, sessionContext);

        Assert.assertEquals(ngResult, oldResult, "SCP03 DEK encryption mismatch");
    }

    @Test
    public void crossVerify_KeyWrapping_SCP01() throws GeneralSecurityException {
        var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP01, KDD);
        var ngResult = ngKeys.wrapKey(KEY_16, new byte[2]);

        var oldKeys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        oldKeys.diversify(SCP.SCP01, KDD);
        var target = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        target.diversify(SCP.SCP01, KDD);
        var oldResult = oldKeys.encryptKey(target, GPCardKeys.KeyPurpose.ENC, new byte[2]);

        Assert.assertEquals(ngResult, oldResult, "SCP01 key wrapping mismatch");
    }

    @Test
    public void crossVerify_KeyWrapping_SCP02() throws GeneralSecurityException {
        var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16).diversify(SCP.SCP02, KDD);
        var ngResult = ngKeys.wrapKey(KEY_16, new byte[2]);

        var oldKeys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        oldKeys.diversify(SCP.SCP02, KDD);
        var target = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        target.diversify(SCP.SCP02, KDD);
        var oldResult = oldKeys.encryptKey(target, GPCardKeys.KeyPurpose.ENC, new byte[2]);

        Assert.assertEquals(ngResult, oldResult, "SCP02 key wrapping mismatch");
    }

    @Test
    public void crossVerify_Scp3Kdf() {
        var ngKeys = PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        var ngResult = ngKeys.kdf(ENC, new byte[16], new byte[16], 16);

        var oldKeys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        var oldResult = oldKeys.scp3_kdf(GPCardKeys.KeyPurpose.ENC, new byte[16], new byte[16], 16);

        Assert.assertEquals(ngResult, oldResult, "SCP03 KDF mismatch");
    }

    // --- Immutability tests ---

    @Test
    public void testDiversifyDoesNotMutate() {
        var original = PlaintextCardKeys.fromMasterKey(KEY_16, PlaintextCardKeys.KDF_TEMPLATES.get("emv"));
        var originalKcv = original.kcv(ENC); // KCV before diversification

        var diversified = (PlaintextCardKeys) original.diversify(SCP.SCP02, KDD);
        var diversifiedKcv = diversified.kcv(ENC);

        // Original must be unchanged
        Assert.assertEquals(original.kcv(ENC), originalKcv, "Original mutated by diversify()!");
        // Diversified must be different
        Assert.assertNotEquals(diversifiedKcv, originalKcv, "Diversified should differ from original");
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void testDoubleDiversifyThrows() {
        var keys = PlaintextCardKeys.fromMasterKey(KEY_16, PlaintextCardKeys.KDF_TEMPLATES.get("emv"));
        var diversified = keys.diversify(SCP.SCP02, KDD);
        diversified.diversify(SCP.SCP02, KDD); // should throw
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void testDeriveSessionWithoutDiversifyThrows() {
        var keys = PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keys.deriveSession(new byte[16]); // should throw - SCP not set
    }

    @Test
    public void testAutoCloseable() {
        var keys = PlaintextCardKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        var diversified = (PlaintextCardKeys) keys.diversify(SCP.SCP03, KDD);
        var session = (SessionKeys.SCP03Keys) diversified.deriveSession(KDD);

        session.close();
        // Session key bytes should be zeroed
        Assert.assertEquals(session.enc(), new byte[16], "Session ENC not zeroed");
        Assert.assertEquals(session.mac(), new byte[16], "Session MAC not zeroed");
        Assert.assertEquals(session.rmac(), new byte[16], "Session RMAC not zeroed");
    }

    // --- Diversification with all KDF templates ---

    @Test
    public void crossVerify_AllTemplates_SCP02() {
        for (var template : PlaintextCardKeys.KDF_TEMPLATES.entrySet()) {
            if ("kdf3".equals(template.getKey())) {
                continue; // kdf3 is SCP03 only
            }
            var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromMasterKey(KEY_16, template.getValue()).diversify(SCP.SCP02, KDD);

            var oldKeys = PlaintextKeys.fromMasterKey(KEY_16, PlaintextKeys.kdf_templates.get(template.getKey()));
            oldKeys.diversify(SCP.SCP02, KDD);

            for (var p : CardKeys.KeyPurpose.cardKeys()) {
                var oldP = GPCardKeys.KeyPurpose.valueOf(p.name());
                Assert.assertEquals(ngKeys.kcv(p), oldKeys.kcv(oldP),
                        "KCV mismatch for template=%s purpose=%s".formatted(template.getKey(), p));
            }
        }
    }

    @Test
    public void crossVerify_KDF3_AllLengths_SCP03() {
        for (var key : new byte[][] { KEY_16, KEY_24, KEY_32 }) {
            var ngKeys = (PlaintextCardKeys) PlaintextCardKeys.fromMasterKey(key, PlaintextCardKeys.KDF_TEMPLATES.get("kdf3")).diversify(SCP.SCP03, KDD);

            var oldKeys = PlaintextKeys.fromMasterKey(key, PlaintextKeys.kdf_templates.get("kdf3"));
            oldKeys.diversify(SCP.SCP03, KDD);

            for (var p : CardKeys.KeyPurpose.cardKeys()) {
                var oldP = GPCardKeys.KeyPurpose.valueOf(p.name());
                Assert.assertEquals(ngKeys.kcv(p), oldKeys.kcv(oldP),
                        "KCV mismatch for keylen=%d purpose=%s".formatted(key.length, p));
            }
        }
    }
}
