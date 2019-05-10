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
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

// Handles plaintext card keys.
// Supports diversification of card keys with some known algorithms.
public class PlaintextKeys extends GPCardKeys {
    // After diversify() we know for which protocol we have keys for

    static final byte[] defaultKeyBytes = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");

    // Derivation constants
    public static final Map<KeyPurpose, byte[]> SCP02_CONSTANTS;
    public static final Map<KeyPurpose, Byte> SCP03_CONSTANTS;
    public static final Map<KeyPurpose, byte[]> SCP03_KDF_CONSTANTS;
    private static final Logger logger = LoggerFactory.getLogger(PlaintextKeys.class);

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
    private int version = 0;
    private int id = 0;

    // Holds card-specific keys. They shall be diversified in-place, as needed
    private HashMap<KeyPurpose, byte[]> cardKeys = new HashMap<>();

    // Holds session-specific keys
    private HashMap<KeyPurpose, byte[]> sessionKeys = new HashMap<>();

    private PlaintextKeys(byte[] enc, byte[] mac, byte[] dek, Diversification d) {
        cardKeys.put(KeyPurpose.ENC, enc);
        cardKeys.put(KeyPurpose.MAC, mac);
        cardKeys.put(KeyPurpose.DEK, dek);
        diversifier = d;
    }

    public static PlaintextKeys fromMasterKey(byte[] master) {
        return derivedFromMasterKey(master, null, Diversification.NONE);
    }

    public static PlaintextKeys fromMasterKey(byte[] master, byte[] kcv) {
        return derivedFromMasterKey(master, kcv, Diversification.NONE);
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

    // Currently only support 3DES methods
    // Purpose defines the magic constants for diversification
    public static byte[] diversify(byte[] k, KeyPurpose usage, byte[] kdd, Diversification method) throws GPException {
        try {
            final byte[] kv;

            if (method == Diversification.KDF3) {
                return GPCrypto.scp03_kdf(k, new byte[]{}, GPUtils.concatenate(SCP03_KDF_CONSTANTS.get(usage), kdd), k.length);
            } else {
                // shift around and fill initialize update data as required.
                if (method == Diversification.VISA2) {
                    kv = fillVisa2(kdd, usage);
                } else if (method == Diversification.EMV) {
                    kv = fillEmv(kdd, usage);
                } else
                    throw new IllegalStateException("Unknown diversification method");

                Cipher cipher = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(GPCrypto.resizeDES(k, 24), "DESede"));

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
        data[7] = 0x01;
        System.arraycopy(kdd, 0, data, 8, 4);
        System.arraycopy(kdd, 8, data, 12, 2);
        data[14] = (byte) 0x0F;
        data[15] = 0x01;
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
    public int getVersion() {
        return version;
    }

    @Override
    public byte[] encrypt(byte[] data) {
        //TODO
        if (1 == 1)
            throw new RuntimeException("Not implemented");
        if (scp == GPSecureChannel.SCP02)
            throw new GPException("SCP02 DEK is session-based");

        if (scp == GPSecureChannel.SCP01) {

        }

        if (scp == GPSecureChannel.SCP03) {

        }

        return new byte[0];
    }

    @Override
    public byte[] encryptKey(GPCardKeys key, KeyPurpose p) throws GeneralSecurityException {
        if (!(key instanceof PlaintextKeys))
            throw new IllegalArgumentException(getClass().getName() + " can only handle " + getClass().getName());
        PlaintextKeys other = (PlaintextKeys) key;
        logger.debug("Encrypting {} value {} with {}", p, HexUtils.bin2hex(other.cardKeys.get(p)), HexUtils.bin2hex(cardKeys.get(KeyPurpose.DEK)));
        switch (scp) {
            case SCP01:
                return GPCrypto.dek_encrypt_des(cardKeys.get(KeyPurpose.DEK), other.cardKeys.get(p));
            case SCP02:
                logger.debug("Encrypting {} value {} with {}", p, HexUtils.bin2hex(other.cardKeys.get(p)), HexUtils.bin2hex(sessionKeys.get(KeyPurpose.DEK)));
                return GPCrypto.dek_encrypt_des(sessionKeys.get(KeyPurpose.DEK), other.cardKeys.get(p));
            case SCP03:
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
    public GPSessionKeys getSessionKeys(byte[] kdd) {
        // Calculate session keys
        for (Map.Entry<KeyPurpose, byte[]> e : cardKeys.entrySet()) {
            switch (scp) {
                case SCP01:
                    sessionKeys.put(e.getKey(), deriveSessionKeySCP01(e.getValue(), e.getKey(), kdd));
                    break;
                case SCP02:
                    sessionKeys.put(e.getKey(), deriveSessionKeySCP02(e.getValue(), e.getKey(), kdd));
                    // FIXME: RMAC missing
                    break;
                case SCP03:
                    sessionKeys.put(e.getKey(), deriveSessionKeySCP03(e.getValue(), e.getKey(), kdd));
                    // Also make a RMAC key
                    if (e.getKey() == KeyPurpose.MAC) {
                        sessionKeys.put(KeyPurpose.RMAC, deriveSessionKeySCP03(e.getValue(), KeyPurpose.RMAC, kdd));
                    }
                    break;
                default:
                    throw new GPException("Illegal SCP");

            }
        }
        return new GPSessionKeys(this, sessionKeys.get(KeyPurpose.ENC), sessionKeys.get(KeyPurpose.MAC), sessionKeys.get(KeyPurpose.RMAC));
    }

    @Override
    public byte[] kcv(KeyPurpose p) {
        if (scp == GPSecureChannel.SCP03)
            return GPCrypto.kcv_aes(cardKeys.get(p));
        return GPCrypto.kcv_3des(cardKeys.get(p));
    }

    public void setVersion(int version) {
        this.version = version;
    }

    private byte[] deriveSessionKeySCP01(byte[] cardKey, KeyPurpose p, byte[] kdd) {
        // RMAC is not supported
        if (!(p == KeyPurpose.ENC || p == KeyPurpose.MAC || p == KeyPurpose.DEK)) {
            throw new IllegalArgumentException("SCP 01 has only ENC, MAC, DEK: " + p);
        }

        // DEK is not session based.
        if (p == KeyPurpose.DEK)
            return cardKey;

        byte[] derivationData = new byte[16];
        System.arraycopy(kdd, 12, derivationData, 0, 4);
        System.arraycopy(kdd, 0, derivationData, 4, 4);
        System.arraycopy(kdd, 8, derivationData, 8, 4);
        System.arraycopy(kdd, 4, derivationData, 12, 4);

        try {
            Cipher cipher = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(GPCrypto.resizeDES(cardKey, 24), "DESede"));
            return cipher.doFinal(derivationData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("Can not calculate session keys", e);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Session key calculation failed", e);
        }
    }

    private byte[] deriveSessionKeySCP02(byte[] cardKey, KeyPurpose p, byte[] sequence) {
        if (p != KeyPurpose.ENC && p != KeyPurpose.MAC && p != KeyPurpose.DEK && p != KeyPurpose.RMAC) {
            throw new IllegalArgumentException("SCP02 has only ENC, MAC, DEK, RMAC: " + p);
        }
        try {
            Cipher cipher = Cipher.getInstance(GPCrypto.DES3_CBC_CIPHER);
            byte[] derivationData = new byte[16];
            System.arraycopy(sequence, 0, derivationData, 2, 2);
            System.arraycopy(SCP02_CONSTANTS.get(p), 0, derivationData, 0, 2);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(GPCrypto.resizeDES(cardKey, 24), "DESede"), GPCrypto.iv_null_8);
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
    public GPCardKeys diversify(GPSecureChannel scp, byte[] kdd) {
        this.scp = scp;
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

        return String.format("ENC=%s (KCV: %s) MAC=%s (KCV: %s) DEK=%s (KCV: %s) for %s", enc, enc_kcv, mac, mac_kcv, dek, dek_kcv, scp);
    }

    @Override
    public int getID() {
        return id;
    }

    public void setDiversifier(Diversification diversifier) {
        this.diversifier = diversifier;
    }

    // diversification methods
    public enum Diversification {
        NONE, VISA2, EMV, KDF3
    }
}
