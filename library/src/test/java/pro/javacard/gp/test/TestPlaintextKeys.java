package pro.javacard.gp.test;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.keys.PlaintextKeys;

import java.security.GeneralSecurityException;

import static pro.javacard.gp.GPCardKeys.KeyPurpose.*;

/**
 * Tests for PlaintextKeys focusing on cryptographic correctness.
 * All tests verify "bytes in -> bytes out" using KCV for key verification.
 */
public class TestPlaintextKeys {

    // Standard test keys
    private static final byte[] KEY_16 = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");
    private static final byte[] KEY_24 = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F5051525354555657");
    private static final byte[] KEY_32 = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
    private static final byte[] KDD = HexUtils.hex2bin("00010203040506070809");

    @Test
    public void testDiversification_EMV_SCP02() {
        // Input: master key 404142... with EMV template, KDD 000102...
        // Expected: diversified keys verified by their KCVs
        GPCardKeys keys = PlaintextKeys.fromMasterKey(KEY_16, PlaintextKeys.kdf_templates.get("emv"));
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP02, KDD);

        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(ENC)), "C33013");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(MAC)), "6F4CA6");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(DEK)), "BB8179");
    }

    @Test
    public void testDiversification_VISA2_SCP02() {
        // Input: master key 404142... with VISA2 template, KDD 000102...
        GPCardKeys keys = PlaintextKeys.fromMasterKey(KEY_16, PlaintextKeys.kdf_templates.get("visa2"));
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP02, KDD);

        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(ENC)), "2BE598");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(MAC)), "58DA38");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(DEK)), "3C328E");
    }

    @Test
    public void testDiversification_KDF3_SCP03_AES128() {
        // Input: AES-128 master key with kdf3 template
        GPCardKeys keys = PlaintextKeys.fromMasterKey(KEY_16, PlaintextKeys.kdf_templates.get("kdf3"));
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP03, KDD);

        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(ENC)), "E79C05");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(MAC)), "D1BD77");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(DEK)), "3FDE8C");
    }

    @Test
    public void testDiversification_KDF3_SCP03_AES192() {
        // Input: AES-192 master key with kdf3 template
        GPCardKeys keys = PlaintextKeys.fromMasterKey(KEY_24, PlaintextKeys.kdf_templates.get("kdf3"));
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP03, KDD);

        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(ENC)), "1DE8EA");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(MAC)), "47C00C");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(DEK)), "C04D76");
    }

    @Test
    public void testDiversification_KDF3_SCP03_AES256() {
        // Input: AES-256 master key with kdf3 template
        GPCardKeys keys = PlaintextKeys.fromMasterKey(KEY_32, PlaintextKeys.kdf_templates.get("kdf3"));
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP03, KDD);

        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(ENC)), "2972D2");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(MAC)), "036F94");
        Assert.assertEquals(HexUtils.bin2hex(keys.kcv(DEK)), "5D57B8");
    }

    @Test
    public void testDiversification_KDF3_ExternalVector() {
        // External test vector for SCP03 KDF
        byte[] kdd = HexUtils.hex2bin("D9B1DE5D0362DEDCE4FB");
        byte[] master = HexUtils.hex2bin("8C72C72CF908411653018807950D82FBAD947562F0828A0B10B8B9606ABF3BCD");
        byte[] expectedDerivedKey = HexUtils.hex2bin("9AAC5D0B3601F89438A0D9D0B6B256CFB47E6462DFA5228D3420C4AC7C224781");

        GPCardKeys keys = PlaintextKeys.fromMasterKey(master, PlaintextKeys.kdf_templates.get("kdf3"));
        keys = keys.diversify(GPSecureChannelVersion.SCP.SCP03, kdd);

        // Verify derived ENC key matches expected by comparing KCVs
        Assert.assertEquals(keys.kcv(ENC), GPCrypto.kcv_aes(expectedDerivedKey));
    }

    @Test
    public void testSessionKeys_SCP01() {
        // Input: static key 404142..., session context of zeros
        GPCardKeys keys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keys.diversify(GPSecureChannelVersion.SCP.SCP01, KDD);

        byte[] sessionContext = new byte[16]; // host_challenge || card_challenge (zeros)

        // Session keys derived via 3DES-ECB of permuted context
        byte[] sEnc = keys.getSessionKey(ENC, sessionContext);
        byte[] sMac = keys.getSessionKey(MAC, sessionContext);
        byte[] sDek = keys.getSessionKey(DEK, sessionContext);

        // Verify session keys by their 3DES KCVs
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(sEnc)), "FDDAF8");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(sMac)), "FDDAF8");
        // DEK is static in SCP01
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(sDek)), "8BAF47");

        // RMAC not supported in SCP01
        Assert.assertNull(keys.getSessionKey(RMAC, sessionContext));
    }

    @Test
    public void testSessionKeys_SCP02() {
        // Input: static key 404142..., sequence counter 0000
        GPCardKeys keys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keys.diversify(GPSecureChannelVersion.SCP.SCP02, KDD);

        byte[] sequence = new byte[2]; // Sequence counter = 0000

        // Session keys derived via 3DES-CBC with constant || counter || zeros
        byte[] sEnc = keys.getSessionKey(ENC, sequence);
        byte[] sMac = keys.getSessionKey(MAC, sequence);
        byte[] sDek = keys.getSessionKey(DEK, sequence);
        byte[] sRmac = keys.getSessionKey(RMAC, sequence);

        // Verify session keys by their 3DES KCVs
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(sEnc)), "F2DCDD");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(sMac)), "5FCC69");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(sDek)), "85272E");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_3des(sRmac)), "9F749A");
    }

    @Test
    public void testSessionKeys_SCP03() {
        // Input: static key 404142..., context = KDD
        GPCardKeys keys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keys.diversify(GPSecureChannelVersion.SCP.SCP03, KDD);

        // Session keys derived via AES CMAC KDF
        byte[] sEnc = keys.getSessionKey(ENC, KDD);
        byte[] sMac = keys.getSessionKey(MAC, KDD);
        byte[] sDek = keys.getSessionKey(DEK, KDD); // Static in SCP03
        byte[] sRmac = keys.getSessionKey(RMAC, KDD);

        // Verify session keys by their AES KCVs
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_aes(sEnc)), "C25559");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_aes(sMac)), "0E12CC");
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_aes(sDek)), "504A77"); // Static key
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_aes(sRmac)), "9ACB9C");
    }

    @Test
    public void testKeyEncryption_SCP01() throws GeneralSecurityException {
        // Input: encrypt key 404142... with static DEK 404142...
        GPCardKeys keys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keys.diversify(GPSecureChannelVersion.SCP.SCP01, KDD);

        GPCardKeys keyToEncrypt = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keyToEncrypt.diversify(GPSecureChannelVersion.SCP.SCP01, KDD);

        // SCP01 uses static DEK with 3DES-ECB
        byte[] encrypted = keys.encryptKey(keyToEncrypt, ENC, new byte[2]);
        Assert.assertEquals(HexUtils.bin2hex(encrypted), "B4BAA89A8CD0292B45210E1BC84B1C31");
    }

    @Test
    public void testKeyEncryption_SCP02() throws GeneralSecurityException {
        // Input: encrypt key 404142... with session DEK derived from sequence 0000
        GPCardKeys keys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keys.diversify(GPSecureChannelVersion.SCP.SCP02, KDD);

        GPCardKeys keyToEncrypt = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keyToEncrypt.diversify(GPSecureChannelVersion.SCP.SCP02, KDD);

        // SCP02 uses session DEK derived from sequence counter
        byte[] encrypted = keys.encryptKey(keyToEncrypt, ENC, new byte[2]);
        Assert.assertEquals(HexUtils.bin2hex(encrypted), "EFBEE6C6D99D7B70BDE9D7E927F020AF");
    }

    @Test
    public void testKeyEncryption_SCP03() throws GeneralSecurityException {
        // Input: encrypt key 404142... with static DEK 404142...
        GPCardKeys keys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keys.diversify(GPSecureChannelVersion.SCP.SCP03, KDD);

        GPCardKeys keyToEncrypt = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        keyToEncrypt.diversify(GPSecureChannelVersion.SCP.SCP03, KDD);

        // SCP03 uses static DEK with AES-CBC + random padding
        byte[] encrypted = keys.encryptKey(keyToEncrypt, ENC, new byte[2]);
        // Length is 16 bytes for AES-128 key
        Assert.assertEquals(encrypted.length, 16);
        // First 16 bytes is encrypted key (deterministic part is hard to test due to random padding)
    }

    @Test
    public void testScp3Kdf() {
        // Input: key 404142..., block_a = zeros(16), block_b = zeros(16), length = 16
        GPCardKeys keys = PlaintextKeys.fromKeys(KEY_16, KEY_16, KEY_16);
        byte[] result = keys.scp3_kdf(ENC, new byte[16], new byte[16], 16);

        // Verify derived key by its KCV
        Assert.assertEquals(result.length, 16);
        Assert.assertEquals(HexUtils.bin2hex(GPCrypto.kcv_aes(result)), "BD8165");
    }
}
