/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-present Martin Paljak, martin@martinpaljak.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static pro.javacard.gp.GPSecureChannelVersion.SCP.*;

// Handles plaintext card keys.
// Supports diversification of card keys with a few known algorithms.
class PlaintextKeys extends GPCardKeys {
    private static final Logger logger = LoggerFactory.getLogger(PlaintextKeys.class);

    // After diversify() we know for which protocol we have keys for, unless known before
    static final byte[] defaultKeyBytes = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");

    // Derivation constants
    public static final Map<KeyPurpose, byte[]> SCP02_CONSTANTS;
    public static final Map<KeyPurpose, Byte> SCP03_CONSTANTS;
    public static final Map<KeyPurpose, byte[]> SCP03_KDF_CONSTANTS;

    static {
        HashMap<KeyPurpose, byte[]> scp2 = new HashMap<>();
        scp2.put(KeyPurpose.MAC, new byte[]{(byte) 0x01, (byte) 0x01});
        scp2.put(KeyPurpose.RMAC, new byte[]{(byte) 0x01, (byte) 0x02});
        scp2.put(KeyPurpose.DEK, new byte[]{(byte) 0x01, (byte) 0x81});
        scp2.put(KeyPurpose.ENC, new byte[]{(byte) 0x01, (byte) 0x82});
        SCP02_CONSTANTS = Collections.unmodifiableMap(scp2);

        HashMap<KeyPurpose, Byte> scp3 = new HashMap<>();
        scp3.put(KeyPurpose.ENC, (byte) 0x04);
        scp3.put(KeyPurpose.MAC, (byte) 0x06);
        scp3.put(KeyPurpose.RMAC, (byte) 0x07);
        SCP03_CONSTANTS = Collections.unmodifiableMap(scp3);

        HashMap<KeyPurpose, byte[]> scp3kdf = new HashMap<>();
        scp3kdf.put(KeyPurpose.ENC, HexUtils.hex2bin("0000000100"));
        scp3kdf.put(KeyPurpose.MAC, HexUtils.hex2bin("0000000200"));
        scp3kdf.put(KeyPurpose.DEK, HexUtils.hex2bin("0000000300"));
        SCP03_KDF_CONSTANTS = Collections.unmodifiableMap(scp3kdf);
    }

    // If diverisification is to be used
    KDF kdf;

    // Keyset version
    private int version = 0x00;

    // Holds the unmodified master key
    private byte[] masterKey;

    // Holds card-specific keys. They shall be diversified in-place, as needed
    private HashMap<KeyPurpose, byte[]> cardKeys = new HashMap<>();

    private PlaintextKeys(byte[] master, KDF d) {
        this(master, master, master, d);
        masterKey = master.clone();
    }

    private PlaintextKeys(byte[] enc, byte[] mac, byte[] dek, KDF d) {
        cardKeys.put(KeyPurpose.ENC, enc.clone());
        cardKeys.put(KeyPurpose.MAC, mac.clone());
        cardKeys.put(KeyPurpose.DEK, dek.clone());
        kdf = d;
    }

    public static Optional<PlaintextKeys> fromEnvironment() {
        return fromEnvironment(System.getenv(), "GP_KEY");
    }

    static byte[] validateKey(byte[] k) {
        if (k.length != 16 && k.length != 24 && k.length != 32) {
            throw new IllegalArgumentException(String.format("Invalid key length %d: %s", k.length, HexUtils.bin2hex(k)));
        }
        return k;
    }

    public static Optional<PlaintextKeys> fromBytes(byte[] enc, byte[] mac, byte[] dek, byte[] mk, KDF kdf, byte[] kdd, int ver) {
        if ((enc != null || mac != null || dek != null) && (enc == null || mac == null || dek == null || mk != null)) {
            throw new IllegalArgumentException("Either all or nothing of enc/mac/dek keys must be set, and no mk at the same time!");
        }

        if (enc != null && mac != null && dek != null) {
            logger.trace("Using three individual keys");
            byte[] encbytes = validateKey(enc);
            byte[] macbytes = validateKey(mac);
            byte[] dekbytes = validateKey(dek);

            PlaintextKeys keys = PlaintextKeys.fromKeys(encbytes, macbytes, dekbytes);
            if (ver != 0) {
                keys.setVersion(ver);
            }
            if (kdf != null) {
                logger.warn("Different keys and using derivation, is this right?");
                keys.setDiversifier(kdf);
            }
            return Optional.of(keys);
        } else if (mk != null) {
            logger.trace("Using a master key");
            byte[] master = validateKey(mk);
            PlaintextKeys keys = PlaintextKeys.fromMasterKey(master);
            if (kdf != null) {
                keys.setDiversifier(kdf);
            } else {
                logger.warn("Using master key without derivation, is this right?");
            }

            // If the actual KDD does not match for some reason what is returned by the card, allow for easy override
            if (kdd != null) {
                keys.kdd = kdd.clone();
            }
            if (ver != 0) {
                keys.setVersion(ver);
            }
            return Optional.of(keys);
        } else
            return Optional.empty();
    }

    public static Optional<PlaintextKeys> fromStrings(String enc, String mac, String dek, String mk, String div, String kdd, String ver) {
        if ((enc != null || mac != null || dek != null) && (enc == null || mac == null || dek == null || mk != null)) {
            throw new IllegalArgumentException("Either all or nothing of enc/mac/dek keys must be set, and no mk at the same time!");
        }
        if (enc != null && mac != null && dek != null) {
            logger.trace("Using three individual keys");
            byte[] encbytes = validateKey(HexUtils.stringToBin(enc));
            byte[] macbytes = validateKey(HexUtils.stringToBin(mac));
            byte[] dekbytes = validateKey(HexUtils.stringToBin(dek));

            PlaintextKeys keys = PlaintextKeys.fromKeys(encbytes, macbytes, dekbytes);
            if (ver != null) {
                keys.setVersion(GPUtils.intValue(ver));
            }
            if (div != null) {
                KDF kdf = KDF.valueOf(div.toUpperCase());
                logger.warn("Different keys and using derivation, is this right?");
                keys.setDiversifier(kdf);
            }
            return Optional.of(keys);
        } else if (mk != null) {
            logger.trace("Using a master key");
            byte[] master = validateKey(HexUtils.stringToBin(mk));
            PlaintextKeys keys = PlaintextKeys.fromMasterKey(master);
            if (div != null) {
                keys.setDiversifier(KDF.valueOf(div.toUpperCase()));
            } else {
                logger.warn("Using master key without derivation, is this right?");
            }

            // If the actual KDD does not match for some reason what is returned by the card, allow for easy override
            if (kdd != null) {
                keys.kdd = HexUtils.stringToBin(kdd);
            }
            if (ver != null) {
                keys.setVersion(GPUtils.intValue(ver));
            }
            return Optional.of(keys);
        } else {
            return Optional.empty();
        }
    }

    // Returns empty if no variables present, throws illegal argument if variable invalid
    public static Optional<PlaintextKeys> fromEnvironment(Map<String, String> env, String prefix) {
        String enc = env.get(prefix + "_ENC");
        String mac = env.get(prefix + "_MAC");
        String dek = env.get(prefix + "_DEK");
        String mk = env.get(prefix);
        String div = env.get(prefix + "_KDF");
        String kdd = env.get(prefix + "_KDD");
        String ver = env.get(prefix + "_VER");
        Optional<PlaintextKeys> r = fromStrings(enc, mac, dek, mk, div, kdd, ver);
        if (r.isPresent())
            logger.debug("Got keys from environment, prefix=" + prefix);
        return r;
    }

    public static PlaintextKeys fromMasterKey(byte[] master) {
        return new PlaintextKeys(master, null);
    }

    public static PlaintextKeys fromMasterKey(byte[] master, KDF kdf) {
        return new PlaintextKeys(master, kdf);
    }

    public static PlaintextKeys defaultKey() {
        return new PlaintextKeys(defaultKeyBytes, null);
    }

    public static PlaintextKeys fromKeys(byte[] enc, byte[] mac, byte[] dek) {
        return new PlaintextKeys(enc, mac, dek, null);
    }

    // Purpose defines the magic constants for diversification
    public static byte[] diversify(byte[] k, KeyPurpose usage, byte[] kdd, KDF method) throws GPException {
        try {
            final byte[] kv;
            if (method == KDF.KDF3) {
                return GPCrypto.scp03_kdf(k, new byte[]{}, GPUtils.concatenate(SCP03_KDF_CONSTANTS.get(usage), kdd), k.length);
            } else {
                // All DES methods rely on encryption
                // shift around and fill initialize update data as required.
                if (method == KDF.VISA2) {
                    kv = fillVisa2(kdd, usage);
                } else if (method == KDF.EMV) {
                    kv = fillEmv(kdd, usage);
                } else
                    throw new IllegalStateException("Unknown diversification method");

                Cipher cipher = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, GPCrypto.des3key(k));
                return cipher.doFinal(kv);
            }
        } catch (BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            throw new GPException("KDF failed", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Can not diversify", e);
        }
    }

    public static byte[] fillVisa2(byte[] kdd, KeyPurpose key) {
        byte[] data = new byte[16];
        System.arraycopy(kdd, 0, data, 0, 2);
        System.arraycopy(kdd, 4, data, 2, 4);
        data[6] = (byte) 0xF0;
        data[7] = key.getValue();
        System.arraycopy(kdd, 0, data, 8, 2);
        System.arraycopy(kdd, 4, data, 10, 4);
        data[14] = (byte) 0x0F;
        data[15] = key.getValue();
        return data;
    }

    // Unknown origin
    public static byte[] fillVisa(byte[] kdd, KeyPurpose key) {
        byte[] data = new byte[16];
        System.arraycopy(kdd, 0, data, 0, 4);
        System.arraycopy(kdd, 8, data, 4, 2);
        data[6] = (byte) 0xF0;
        data[7] = key.getValue();
        System.arraycopy(kdd, 0, data, 8, 4);
        System.arraycopy(kdd, 8, data, 12, 2);
        data[14] = (byte) 0x0F;
        data[15] = key.getValue();
        return data;
    }

    public static byte[] fillEmv(byte[] kdd, KeyPurpose key) {
        byte[] data = new byte[16];
        // 6 rightmost bytes of init update response (which is 10 bytes)
        System.arraycopy(kdd, 4, data, 0, 6);
        data[6] = (byte) 0xF0;
        data[7] = key.getValue();
        System.arraycopy(kdd, 4, data, 8, 6);
        data[14] = (byte) 0x0F;
        data[15] = key.getValue();
        return data;
    }

    public Optional<byte[]> getMasterKey() {
        return Optional.ofNullable(masterKey);
    }

    @Override
    public GPKeyInfo getKeyInfo() {
        // all keys are of same length
        byte[] aKey = cardKeys.get(KeyPurpose.ENC);
        final GPKeyInfo.GPKey type;
        if (aKey.length > 16 || scp == SCP03)
            type = GPKeyInfo.GPKey.AES;
        else
            type = GPKeyInfo.GPKey.DES3;
        return new GPKeyInfo(version, 0x01, aKey.length, type);
    }

    @Override
    // data must be padded by caller
    public byte[] encrypt(byte[] data, byte[] sessionContext) throws GeneralSecurityException {
        if (scp == SCP02) {
            byte[] sdek = deriveSessionKeySCP02(cardKeys.get(KeyPurpose.DEK), KeyPurpose.DEK, sessionContext);
            return GPCrypto.dek_encrypt_des(sdek, data);
        } else if (scp == SCP01) {
            return GPCrypto.dek_encrypt_des(cardKeys.get(KeyPurpose.DEK), data);
        } else if (scp == SCP03) {
            return GPCrypto.dek_encrypt_aes(cardKeys.get(KeyPurpose.DEK), data);
        } else throw new IllegalStateException("Unknown SCP version");
    }

    @Override
    public byte[] encryptKey(GPCardKeys key, KeyPurpose p, byte[] sessionContext) throws GeneralSecurityException {
        if (!(key instanceof PlaintextKeys))
            throw new IllegalArgumentException(getClass().getName() + " can only handle " + getClass().getName());
        PlaintextKeys other = (PlaintextKeys) key;
        switch (scp) {
            case SCP01:
                logger.debug("Encrypting {} value (KCV={}) with DEK (KCV={})", p, HexUtils.bin2hex(other.kcv(p)), HexUtils.bin2hex(kcv(KeyPurpose.DEK)));
                return GPCrypto.dek_encrypt_des(cardKeys.get(KeyPurpose.DEK), other.cardKeys.get(p));
            case SCP02:
                byte[] sdek = deriveSessionKeySCP02(cardKeys.get(KeyPurpose.DEK), KeyPurpose.DEK, sessionContext);
                logger.debug("Encrypting {} value (KCV={}) with S-DEK (KCV={})", p, HexUtils.bin2hex(other.kcv(p)), HexUtils.bin2hex(GPCrypto.kcv_3des(sdek)));
                return GPCrypto.dek_encrypt_des(sdek, other.cardKeys.get(p));
            case SCP03:
                logger.debug("Encrypting {} value (KCV={}) with DEK (KCV={})", p, HexUtils.bin2hex(other.kcv(p)), HexUtils.bin2hex(kcv(KeyPurpose.DEK)));
                byte[] otherkey = other.cardKeys.get(p);
                // Pad with random
                int n = otherkey.length % 16 + 1;
                byte[] plaintext = new byte[n * otherkey.length];
                GPCrypto.random.nextBytes(plaintext);
                System.arraycopy(otherkey, 0, plaintext, 0, otherkey.length);
                // encrypt
                return GPCrypto.dek_encrypt_aes(cardKeys.get(KeyPurpose.DEK), plaintext);
            default:
                throw new GPException("Illegal SCP");
        }
    }

    @Override
    public byte[] getSessionKey(KeyPurpose p, byte[] session_kdd) {
        // Calculate session key (ENC-MAC-DEK[-RMAC])
        switch (scp) {
            case SCP01:
                return deriveSessionKeySCP01(cardKeys.get(p), p, session_kdd);
            case SCP02:
                if (p == KeyPurpose.RMAC) {
                    return deriveSessionKeySCP02(cardKeys.get(KeyPurpose.MAC), KeyPurpose.RMAC, session_kdd);
                } else
                    return deriveSessionKeySCP02(cardKeys.get(p), p, session_kdd);
            case SCP03:
                if (p == KeyPurpose.RMAC) {
                    return deriveSessionKeySCP03(cardKeys.get(KeyPurpose.MAC), KeyPurpose.RMAC, session_kdd);
                } else
                    return deriveSessionKeySCP03(cardKeys.get(p), p, session_kdd);
            default:
                throw new IllegalStateException("Illegal SCP");
        }
    }

    @Override
    public byte[] kcv(KeyPurpose p) {
        byte[] k = cardKeys.get(p);

        if (scp == SCP03)
            return GPCrypto.kcv_aes(k);
        else if (scp == SCP01 || scp == SCP02)
            return GPCrypto.kcv_3des(k);
        else {
            if (k.length == 16) {
                logger.warn("Don't know how to calculate KCV, defaulting to SCP02");
                return GPCrypto.kcv_3des(k);
            } else {
                logger.warn("Don't know how to calculate KCV, defaulting to SCP03");
                return GPCrypto.kcv_aes(k);
            }
        }
    }

    public void setVersion(int version) {
        this.version = version;
    }

    private byte[] deriveSessionKeySCP01(byte[] cardKey, KeyPurpose p, byte[] kdd) {
        if (p == KeyPurpose.DEK)
            return cardKey;

        byte[] derivationData = new byte[16];
        System.arraycopy(kdd, 12, derivationData, 0, 4);
        System.arraycopy(kdd, 0, derivationData, 4, 4);
        System.arraycopy(kdd, 8, derivationData, 8, 4);
        System.arraycopy(kdd, 4, derivationData, 12, 4);

        try {
            Cipher cipher = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, GPCrypto.des3key(cardKey));
            return cipher.doFinal(derivationData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("Can not calculate session keys", e);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Session key calculation failed", e);
        }
    }

    private byte[] deriveSessionKeySCP02(byte[] cardKey, KeyPurpose p, byte[] sequence) {
        try {
            Cipher cipher = Cipher.getInstance(GPCrypto.DES3_CBC_CIPHER);
            byte[] derivationData = new byte[16];
            System.arraycopy(sequence, 0, derivationData, 2, 2);
            System.arraycopy(SCP02_CONSTANTS.get(p), 0, derivationData, 0, 2);
            cipher.init(Cipher.ENCRYPT_MODE, GPCrypto.des3key(cardKey), GPCrypto.iv_null_8);
            return cipher.doFinal(derivationData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("Session keys calculation failed.", e);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Session keys calculation failed.", e);
        }
    }

    private byte[] deriveSessionKeySCP03(byte[] cardKey, KeyPurpose p, byte[] kdd) {
        if (p == KeyPurpose.DEK) {
            return cardKey;
        }
        return GPCrypto.scp03_kdf(cardKey, SCP03_CONSTANTS.get(p), kdd, cardKey.length * 8);
    }


    @Override
    public PlaintextKeys diversify(GPSecureChannelVersion.SCP scp, byte[] kdd) {
        // Set SCP and KDD and diversification state
        super.diversify(scp, kdd);

        // Do nothing
        if (kdf == null)
            return this;

        // Calculate per-card keys from master key(s), if needed
        for (Map.Entry<KeyPurpose, byte[]> e : cardKeys.entrySet()) {
            cardKeys.put(e.getKey(), diversify(e.getValue(), e.getKey(), kdd, kdf));
        }
        return this;
    }


    @Override
    public String toString() {
        String enc = HexUtils.bin2hex(cardKeys.get(KeyPurpose.ENC));
        String enc_kcv = HexUtils.bin2hex(kcv(KeyPurpose.ENC));

        String mac = HexUtils.bin2hex(cardKeys.get(KeyPurpose.MAC));
        String mac_kcv = HexUtils.bin2hex(kcv(KeyPurpose.MAC));

        String dek = HexUtils.bin2hex(cardKeys.get(KeyPurpose.DEK));
        String dek_kcv = HexUtils.bin2hex(kcv(KeyPurpose.DEK));

        return String.format("ENC=%s (KCV: %s) MAC=%s (KCV: %s) DEK=%s (KCV: %s) for %s%s", enc, enc_kcv, mac, mac_kcv, dek, dek_kcv, scp, kdf == null ? "" : String.format(" with %s", kdf));
    }

    public void setDiversifier(KDF kdf) {
        if (this.kdf != null)
            throw new IllegalStateException("KDF already set");
        this.kdf = kdf;
    }

    // diversification methods
    public enum KDF {
        VISA2, EMV, KDF3
    }
}
