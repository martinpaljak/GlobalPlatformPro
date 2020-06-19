/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2019 Martin Paljak, martin@martinpaljak.net
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

import apdu4j.HexUtils;
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
import java.util.*;

// Handles plaintext card keys.
// Supports diversification of card keys with a few known algorithms.
// TODO: make sure only TRACE shows key values and DEBUG uses KCV-s
public class PlaintextKeys extends GPCardKeys {
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

    // If diverisification is to be used, which method
    Diversification diversifier;

    // Keyset version
    private int version = 0x00;

    // Holds card-specific keys. They shall be diversified in-place, as needed
    private HashMap<KeyPurpose, byte[]> cardKeys = new HashMap<>();

    // Holds a copy of session-specific keys. Only relevant for SCP02
    private HashMap<KeyPurpose, byte[]> sessionKeys = new HashMap<>();

    private PlaintextKeys(byte[] enc, byte[] mac, byte[] dek, Diversification d) {
        cardKeys.put(KeyPurpose.ENC, enc);
        cardKeys.put(KeyPurpose.MAC, mac);
        cardKeys.put(KeyPurpose.DEK, dek);
        diversifier = d;
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
                logger.warn("Different keys and using derivation, is this right?");
                Optional<Diversification> d = Optional.ofNullable(Diversification.lookup(div));
                keys.setDiversifier(d.orElseThrow(() -> new IllegalArgumentException("Invalid diversification:  " + div)));
            }
            return Optional.of(keys);
        } else if (mk != null) {
            logger.trace("Using a master key");
            byte[] master = validateKey(HexUtils.stringToBin(mk));
            PlaintextKeys keys = PlaintextKeys.fromMasterKey(master);
            if (div != null) {
                Optional<Diversification> d = Optional.ofNullable(Diversification.lookup(div));
                keys.setDiversifier(d.orElseThrow(() -> new IllegalArgumentException("Invalid diversification:  " + div)));
            } else {
                logger.warn("Using master key without derivation, is this right?");
            }

            // If the actual KDD does not match for some reason what is returned by the card, allow for easy override
            if (kdd != null) {
                byte[] kddbytes = HexUtils.stringToBin(kdd);
                keys.kdd = kddbytes;
            }
            if (ver != null) {
                keys.setVersion(GPUtils.intValue(ver));
            }
            // TODO: KCV
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
        String div = env.get(prefix + "_DIV");
        String kdd = env.get(prefix + "_KDD");
        String ver = env.get(prefix + "_VER");
        Optional<PlaintextKeys> r = fromStrings(enc, mac, dek, mk, div, kdd, ver);
        if (r.isPresent())
            logger.debug("Got keys from environment, prefix=" + prefix);
        return r;
    }

    public static PlaintextKeys fromMasterKey(byte[] master) {
        return derivedFromMasterKey(master, null, Diversification.NONE);
    }

    public static PlaintextKeys defaultKey() {
        return derivedFromMasterKey(defaultKeyBytes, null, Diversification.NONE);
    }

    public static PlaintextKeys derivedFromMasterKey(byte[] master, byte[] kcv, Diversification div) {
        if (kcv != null && kcv.length == 3) {
            byte[] kcv_des = GPCrypto.kcv_3des(master);
            byte[] kcv_aes = GPCrypto.kcv_aes(master);
            if (Arrays.equals(kcv_des, kcv)) {
                logger.debug("KCV matches 3DES");
            } else if (Arrays.equals(kcv_aes, kcv)) {
                logger.debug("KCV matches AES");
            } else {
                String msg = String.format("KCV mismatch: %s vs %s (3DES) or %s (AES)", HexUtils.bin2hex(kcv), HexUtils.bin2hex(kcv_des), HexUtils.bin2hex(kcv_aes));
                throw new IllegalArgumentException(msg);
            }
        }
        return new PlaintextKeys(master, master, master, div);
    }


    public static PlaintextKeys fromKeys(byte[] enc, byte[] mac, byte[] dek) {
        return new PlaintextKeys(enc, mac, dek, Diversification.NONE);
    }

    // Purpose defines the magic constants for diversification
    public static byte[] diversify(byte[] k, KeyPurpose usage, byte[] kdd, Diversification method) throws GPException {
        try {
            final byte[] kv;
            if (method == Diversification.KDF3) {
                return GPCrypto.scp03_kdf(k, new byte[]{}, GPUtils.concatenate(SCP03_KDF_CONSTANTS.get(usage), kdd), k.length);
            } else {
                // All DES methods rely on encryption
                // shift around and fill initialize update data as required.
                if (method == Diversification.VISA2) {
                    kv = fillVisa2(kdd, usage);
                } else if (method == Diversification.EMV) {
                    kv = fillEmv(kdd, usage);
                } else
                    throw new IllegalStateException("Unknown diversification method");

                Cipher cipher = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, GPCrypto.des3key(k));
                return cipher.doFinal(kv);
            }
        } catch (BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            throw new GPException("Diversification failed.", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Can not diversify", e);
        }
    }

    public static final byte[] fillVisa2(byte[] kdd, KeyPurpose key) {
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
    public static final byte[] fillVisa(byte[] kdd, KeyPurpose key) {
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

    public static final byte[] fillEmv(byte[] kdd, KeyPurpose key) {
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

    @Override
    public GPKeyInfo getKeyInfo() {
        // all keys are of same length
        byte[] aKey = cardKeys.get(KeyPurpose.ENC);
        final GPKeyInfo.GPKey type;
        if (aKey.length > 16 || scp == GPSecureChannel.SCP03)
            type = GPKeyInfo.GPKey.AES;
        else
            type = GPKeyInfo.GPKey.DES3;
        return new GPKeyInfo(version, 0x01, aKey.length, type);
    }

    @Override
    // data must be padded by caller
    public byte[] encrypt(byte[] data, byte[] sessionContext) throws GeneralSecurityException {
        if (scp == GPSecureChannel.SCP02) {
            return GPCrypto.dek_encrypt_des(sessionKeys.get(KeyPurpose.DEK), data);
        } else if (scp == GPSecureChannel.SCP01) {
            return GPCrypto.dek_encrypt_des(cardKeys.get(KeyPurpose.DEK), data);
        } else if (scp == GPSecureChannel.SCP03) {
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
                logger.debug("Encrypting {} value (KCV={}) with S-DEK (KCV={})", p, HexUtils.bin2hex(other.kcv(p)), HexUtils.bin2hex(GPCrypto.kcv_3des(sessionKeys.get(KeyPurpose.DEK))));
                return GPCrypto.dek_encrypt_des(sessionKeys.get(KeyPurpose.DEK), other.cardKeys.get(p));
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
    public Map<KeyPurpose, byte[]> getSessionKeys(byte[] session_kdd) {
        // Calculate session keys (ENC-MAC-DEK[-RMAC])
        for (KeyPurpose p : KeyPurpose.cardKeys()) {
            switch (scp) {
                case SCP01:
                    sessionKeys.put(p, deriveSessionKeySCP01(cardKeys.get(p), p, session_kdd));
                    break;
                case SCP02:
                    sessionKeys.put(p, deriveSessionKeySCP02(cardKeys.get(p), p, session_kdd));
                    if (p == KeyPurpose.MAC) {
                        sessionKeys.put(KeyPurpose.RMAC, deriveSessionKeySCP02(cardKeys.get(p), KeyPurpose.RMAC, session_kdd));
                    }
                    break;
                case SCP03:
                    sessionKeys.put(p, deriveSessionKeySCP03(cardKeys.get(p), p, session_kdd));
                    if (p == KeyPurpose.MAC) {
                        sessionKeys.put(KeyPurpose.RMAC, deriveSessionKeySCP03(cardKeys.get(p), KeyPurpose.RMAC, session_kdd));
                    }
                    break;
                default:
                    throw new IllegalStateException("Illegal SCP");
            }
        }
        return sessionKeys;
    }

    @Override
    public byte[] kcv(KeyPurpose p) {
        byte[] k = cardKeys.get(p);

        if (scp == GPSecureChannel.SCP03)
            return GPCrypto.kcv_aes(k);
        else if (scp == GPSecureChannel.SCP01 || scp == GPSecureChannel.SCP02)
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
        byte[] kdf = GPCrypto.scp03_kdf(cardKey, SCP03_CONSTANTS.get(p), kdd, cardKey.length * 8);
        return kdf;
    }


    @Override
    public PlaintextKeys diversify(GPSecureChannel scp, byte[] kdd) {
        // Set SCP and KDD and diversification state
        super.diversify(scp, kdd);

        // Do nothing
        if (diversifier == Diversification.NONE)
            return this;

        // Calculate per-card keys from master key(s), if needed
        for (Map.Entry<KeyPurpose, byte[]> e : cardKeys.entrySet()) {
            cardKeys.put(e.getKey(), diversify(e.getValue(), e.getKey(), kdd, diversifier));
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

        return String.format("ENC=%s (KCV: %s) MAC=%s (KCV: %s) DEK=%s (KCV: %s) for %s%s", enc, enc_kcv, mac, mac_kcv, dek, dek_kcv, scp, diversifier == Diversification.NONE ? "" : String.format(" with %s", diversifier));
    }

    public void setDiversifier(Diversification diversifier) {
        this.diversifier = diversifier;
    }

    // diversification methods
    public enum Diversification {
        NONE, VISA2, EMV, KDF3;

        public static Diversification lookup(String v) {
            for (Diversification d : Diversification.values()) {
                if (d.name().equalsIgnoreCase(v)) {
                    return d;
                }
            }
            return null;
        }
    }
}
