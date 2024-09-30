package pro.javacard.pace;

import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import com.payneteasy.tlv.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

// https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03110/BSI_TR-03110_Part-3-V2_2.pdf?__blob=publicationFile&v=1
// Also: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-0_pdf.pdf?__blob=publicationFile&v=1 ?
// Executing PACE gives two keys, enc and mac
public final class PACE {
    private static final Logger log = LoggerFactory.getLogger(PACE.class);

    private final byte[] keyENC;
    private final byte[] keyMAC;

    public byte[] getENC() {
        return keyENC.clone();
    }

    public byte[] getMAC() {
        return keyMAC.clone();
    }

    private PACE(byte[] keyENC, byte[] keyMAC) {
        this.keyENC = keyENC;
        this.keyMAC = keyMAC;
        log.info("Computed PACE: ENC: {} MAC:{}", Hex.toHexString(keyENC), Hex.toHexString(keyMAC));
    }

    // A.3.2.PACE with ECDH
    // id-PACE-ECDH-GM-AES-CBC-CMAC-256
    private static final byte[] oid = HexUtils.hex2bin("04007F00070202040204"); // 0.4.0.127.0.7.2.2.4.2.4

    static final byte PASSWORD_CAN = 0x02;

    // A.2.1.1 Table 4: Standardized Domain Parameters
    public static enum PACECurve {
        secp256r1(12, ECNamedCurveTable.getParameterSpec("secp256r1")),
        brainpoolp256r1(13, ECNamedCurveTable.getParameterSpec("brainpoolp256r1")),
        secp384r1(15, ECNamedCurveTable.getParameterSpec("secp384r1")),
        brainpoolp384r1(16, ECNamedCurveTable.getParameterSpec("brainpoolp384r1"));

        final byte code;
        final ECParameterSpec spec;

        PACECurve(int code, ECParameterSpec ecParameterSpec) {
            this.code = (byte) code;
            this.spec = ecParameterSpec;
        }
    }

    private final static BerTlvParser parser = new BerTlvParser();

    // B.1.PACE.
    public static PACE executePACE(APDUBIBO c, byte[] aid, String can, PACECurve curve) throws PACEException, IOException, GeneralSecurityException {

        // Select the PACE application
        ResponseAPDU r = c.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid, 256));
        PACEException.check(r);

        // set security environment
        r = c.transmit(set_at(oid, PASSWORD_CAN, curve));
        PACEException.check(r);

        // Step 1: get the encrypted nonce
        r = c.transmit(general_authenticate(new byte[]{0x7c, 0x00}));
        r = PACEException.check(r);
        SCHelpers.trace_tlv(r.getData(), log);

        // Get encrypted nonce
        BerTlv encryptedNonce = require_tag(r.getData(), 0x80);

        // Decrypt with derived CAN PI
        // A.3.3.Encrypted Nonce
        byte[] key = kdf(can.getBytes(StandardCharsets.UTF_8), COUNTER_PI);
        byte[] nonce = AESSecureChannel.decrypt(key, new byte[16], encryptedNonce.getBytesValue());

        // Step 2: mapping ephemeral key
        // Generate ephemeral pace mapping key on curve
        AsymmetricCipherKeyPair host_map = generate(curve.spec);

        // Mapping key public point, uncompressed, is our (PCD) key
        byte[] host_map_pub = ((ECPublicKeyParameters) host_map.getPublic()).getQ().getEncoded(false);

        // GENERAL AUTHENTICATE 81 - Challenge - contains the mapping key public key point in uncompressed format
        BerTlvBuilder payload = new BerTlvBuilder(new BerTag(0x7C)).addBytes(new BerTag(0x81), host_map_pub);

        CommandAPDU apdu2 = general_authenticate(payload.buildArray());

        SCHelpers.trace_tlv(apdu2.getData(), log);
        r = PACEException.check(c.transmit(apdu2));
        SCHelpers.trace_tlv(r.getData(), log);

        // Response is card mapping public key on curve
        BerTlv card_map_tag = require_tag(r.getData(), 0x82);

        // Decode key on mapping curve
        byte[] card_map_pub = decodePublic(curve.spec, card_map_tag.getBytesValue());

        // Check
        if (Arrays.equals(card_map_pub, host_map_pub)) {
            throw new PACEException("PACE: card and host keys can not be equal!");
        }

        // Map new domain parameters
        ECParameterSpec parameters = parameterMap(curve.spec, (ECPrivateKeyParameters) host_map.getPrivate(), card_map_pub, nonce);

        // Generate a ephemeral keypair on the given curve
        AsymmetricCipherKeyPair ephemeral_host = generate(parameters);
        byte[] ephemeral_host_pub = ((ECPublicKeyParameters) ephemeral_host.getPublic()).getQ().getEncoded(false);

        // Perform key agreement
        // GENERAL AUTHENTICATE 83 - Commited challenge
        payload = new BerTlvBuilder(new BerTag(0x7C)).addBytes(new BerTag(0x83), ephemeral_host_pub);
        CommandAPDU apdu3 = general_authenticate(payload.buildArray());

        SCHelpers.trace_tlv(apdu3.getData(), log);
        r = PACEException.check(c.transmit(apdu3));
        SCHelpers.trace_tlv(r.getData(), log);

        // We receive a point on the ephemeral curve
        BerTlv ephemeral_card_tag = require_tag(r.getData(), 0x84);

        // Decode card public key
        byte[] ephemeral_card_pub = decodePublic(parameters, ephemeral_card_tag.getBytesValue());

        // Keys can't be equal
        if (Arrays.equals(ephemeral_host_pub, ephemeral_card_pub))
            throw new PACEException("PACE security violation: equal keys");

        // Step 5 - ECDH on ephemeral curve
        // Calculate shared key k
        byte[] k = generateSharedSecret(curve.spec, ((ECPrivateKeyParameters) ephemeral_host.getPrivate()).getD().toByteArray(), ephemeral_card_pub);
        // Derive key MAC
        byte[] keyMAC = kdf(k, COUNTER_MAC);
        // Derive key ENC
        byte[] keyENC = kdf(k, COUNTER_ENC);


        // Calculate our authentication token.
        byte[] host_auth_token = aes_mac8(keyMAC, auth_token(ephemeral_card_pub));
        payload = new BerTlvBuilder(new BerTag(0x7C)).addBytes(new BerTag(0x85), host_auth_token);

        CommandAPDU apdu4 = general_authenticate_last(payload.buildArray());

        SCHelpers.trace_tlv(apdu4.getData(), log);
        r = PACEException.check(c.transmit(apdu4));
        SCHelpers.trace_tlv(r.getData(), log);

        // Verify card auth token
        BerTlv auth_token_card = require_tag(r.getData(), 0x86);
        byte[] my_auth_token_card = aes_mac8(keyMAC, auth_token(ephemeral_host_pub));
        if (!Arrays.equals(auth_token_card.getBytesValue(), my_auth_token_card)) {
            throw new PACEException("PACE: invalid card auth token: " + HexUtils.bin2hex(r.getData()));
        } else {
            log.info("Card authenticated");
        }
        return new PACE(keyENC, keyMAC);
    }

    static BerTlv require_tag(byte[] response, int tag) throws PACEException {
        BerTlvs tlvs = parser.parse(response);
        BerTlv found = tlvs.find(new BerTag(tag));
        if (found == null)
            throw new PACEException(String.format("PACE: invalid response, missing tag 0x%02X: %s", tag, HexUtils.bin2hex(response)));
        return found;
    }

    static AsymmetricCipherKeyPair generate(ECParameterSpec p) {
        ECDomainParameters domain = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domain, new SecureRandom());
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(keyGenParams);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        return keyPair;
    }

    static byte[] decodePublic(ECParameterSpec p, byte[] data) {
        ECDomainParameters domain = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECPoint q = domain.getCurve().decodePoint(data);
        ECPublicKeyParameters tmp = new ECPublicKeyParameters(q, domain);
        return tmp.getQ().getEncoded(false);
    }

    // B.14.2. General Authenticate
    private static CommandAPDU general_authenticate(byte[] payload) {
        return new CommandAPDU(0x10, 0x86, 0x00, 0x00, payload, 256);
    }

    private static CommandAPDU general_authenticate_last(byte[] payload) {
        return new CommandAPDU(0x00, 0x86, 0x00, 0x00, payload, 256);
    }

    // B.14.1. MSE:Set AT
    private static CommandAPDU set_at(byte[] oid, byte password, PACECurve curve) throws IOException {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(new BerTlvBuilder().addBytes(new BerTag(0x80), oid).buildArray()); // Cryptographic mechanism reference
        payload.write(new BerTlvBuilder().addByte(new BerTag(0x83), password).buildArray()); // Password reference - CAN
        payload.write(new BerTlvBuilder().addByte(new BerTag(0x84), curve.code).buildArray());
        // P1/P2: PACE: Set Authentication Template for mutual authentication.
        return new CommandAPDU(0x00, 0x22, 0xC1, 0xA4, payload.toByteArray(), 256);
    }

    // A.2.3. Key Derivation Function SHA256 of: secret || nonce || counter (4 bytes)
    private static final byte COUNTER_ENC = 0x01;
    private static final byte COUNTER_MAC = 0x02;
    private static final byte COUNTER_PI = 0x03;

    static byte[] kdf(byte[] secret, byte counter) throws GeneralSecurityException {
        return kdf(secret, counter, null);
    }

    private static byte[] kdf(byte[] secret, byte counter, byte[] nonce) throws GeneralSecurityException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] c = {(byte) 0x00, (byte) 0x00, (byte) 0x00, counter};

        sha256.update(secret);
        // Note: The nonce r is used for Chip Authentication version 2 only (always null for us currently)
        if (nonce != null) {
            sha256.update(nonce);
        }
        sha256.update(c);
        return sha256.digest(); // No need to cut, 256 bits is keylen
    }

    // A.3.4.1.Generic Mapping - ephemeral domain parameters.
    private static ECParameterSpec parameterMap(ECParameterSpec curve, ECPrivateKeyParameters mapKey, byte[] card_pub, byte[] nonce) {
        ECPoint card_map_pub = curve.getCurve().decodePoint(card_pub);
        BigInteger d = mapKey.getD();
        BigInteger s = new BigInteger(1, nonce);

        ECPoint h = card_map_pub.multiply(curve.getH().multiply(d));
        ECPoint newG = curve.getG().multiply(s).add(h);

        return new ECParameterSpec(curve.getCurve(), newG, curve.getN(), curve.getH());
    }


    // ECDH on curve, X coordinate only
    public static byte[] generateSharedSecret(ECParameterSpec curve, byte[] sk, byte[] pk) {
        BigInteger d = new BigInteger(1, sk);
        ECPoint q = curve.getCurve().decodePoint(pk);
        ECPoint k = q.multiply(d);
        return positive(k.normalize().getXCoord().toBigInteger().toByteArray());
    }

    public static byte[] positive(byte[] bytes) {
        if (bytes[0] == 0 && bytes.length % 2 == 1) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    // A.2.4.2. AES
    static byte[] aes_mac8(byte[] key, byte[] data) {
        byte[] fullmac = new byte[16];
        CMac cMAC = new CMac(AESEngine.newInstance());
        cMAC.init(new KeyParameter(key));
        cMAC.update(data, 0, data.length);
        cMAC.doFinal(fullmac, 0);
        return Arrays.copyOf(fullmac, 8);
    }

    // tags 0x85 / 0x86 during step 4. Key is uncompressed public key point
    private static byte[] auth_token(byte[] key) {
        // D.3.3. Elliptic Curve Public Keys for OID and key,
        // D.2. Data Objects for 0x7F49 (Public Key)
        BerTlvBuilder payload = new BerTlvBuilder(new BerTag(0x7F, 0x49))
                .addBytes(new BerTag(0x06), oid)
                .addBytes(new BerTag(0x86), key);
        return payload.buildArray();
    }
}
