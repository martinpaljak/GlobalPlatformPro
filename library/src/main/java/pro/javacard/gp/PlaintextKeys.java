/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2017 Martin Paljak, martin@martinpaljak.net
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
import pro.javacard.gp.GPKey.Type;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

// Handles plaintext card keys.
// Supports diversification of card keys with some known algorithms.
public class PlaintextKeys extends GPSessionKeyProvider {
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
    Diversification diversifier = null;

    // Keyset version
    private int version = 0;
    private int id = 0;
    // Holds card-specific keys. They shall be diversified in-place, as needed
    private HashMap<KeyPurpose, GPKey> cardKeys = new HashMap<>();
    // Holds session-specific keys
    private HashMap<KeyPurpose, GPKey> sessionKeys = new HashMap<>();

    private PlaintextKeys() {
    }

    public static PlaintextKeys fromMasterKey(GPKey master) {
        return derivedFromMasterKey(master, null);
    }

    public static PlaintextKeys derivedFromMasterKey(GPKey master, Diversification div) {
        PlaintextKeys p = new PlaintextKeys();
        p.cardKeys.put(KeyPurpose.ENC, new GPKey(master.getBytes()));
        p.cardKeys.put(KeyPurpose.MAC, new GPKey(master.getBytes()));
        p.cardKeys.put(KeyPurpose.DEK, new GPKey(master.getBytes()));
        p.diversifier = div;
        return p;
    }

    public static PlaintextKeys fromKeys(GPKey enc, GPKey mac, GPKey kek) {
        PlaintextKeys p = new PlaintextKeys();
        p.cardKeys.put(KeyPurpose.ENC, enc);
        p.cardKeys.put(KeyPurpose.MAC, mac);
        p.cardKeys.put(KeyPurpose.DEK, kek);
        return p;
    }

    // Currently only support 3DES methods
    // Purpose defines the magic constants for diversification
    public static GPKey diversify(GPKey k, KeyPurpose usage, byte[] kdd, Diversification method) throws GPException {
        try {
            final byte[] kv;

            if (method == Diversification.KDF3) {
                kv = GPCrypto.scp03_kdf(k.getBytes(), new byte[]{}, GPUtils.concatenate(SCP03_KDF_CONSTANTS.get(usage), kdd), k.getLength());
                return new GPKey(kv, Type.AES);
            } else {
                // shift around and fill initialize update data as required.
                if (method == Diversification.VISA2) {
                    kv = fillVisa2(kdd, usage);
                } else if (method == Diversification.EMV) {
                    kv = fillEmv(kdd, usage);
                } else
                    throw new IllegalStateException("Unknown diversification method");

                Cipher cipher = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, k.getKeyAs(Type.DES3));
                // The resulting key can be interpreted as AES key (SCE 6.0) thus return as a RAW
                // Caller can cast to whatever needed
                return new GPKey(cipher.doFinal(kv));
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

    public void setVersion(int version) {
        this.version = version;
    }

    private GPKey deriveSessionKeySCP01(GPKey cardKey, KeyPurpose p, byte[] host_challenge, byte[] card_challenge) {
        // RMAC is not supported
        if (!(p == KeyPurpose.ENC || p == KeyPurpose.MAC || p == KeyPurpose.DEK)) {
            throw new IllegalArgumentException("SCP 01 has only ENC, MAC, DEK: " + p);
        }

        // DEK is not session based.
        if (p == KeyPurpose.DEK)
            return cardKey;

        byte[] derivationData = new byte[16];
        System.arraycopy(card_challenge, 4, derivationData, 0, 4);
        System.arraycopy(host_challenge, 0, derivationData, 4, 4);
        System.arraycopy(card_challenge, 0, derivationData, 8, 4);
        System.arraycopy(host_challenge, 4, derivationData, 12, 4);

        try {
            Cipher cipher = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, cardKey.getKeyAs(Type.DES3));
            return new GPKey(cipher.doFinal(derivationData), Type.DES3);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("Can not calculate session keys", e);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Session key calculation failed", e);
        }
    }

    private GPKey deriveSessionKeySCP02(GPKey cardKey, KeyPurpose p, byte[] sequence) {
        if (p != KeyPurpose.ENC && p != KeyPurpose.MAC && p != KeyPurpose.DEK && p != KeyPurpose.RMAC) {
            throw new IllegalArgumentException("SCP 02 has only ENC, MAC, DEK, RMAC: " + p);
        }
        // TODO: clarify RMAC/DEK
        try {
            Cipher cipher = Cipher.getInstance(GPCrypto.DES3_CBC_CIPHER);
            byte[] derivationData = new byte[16];
            System.arraycopy(sequence, 0, derivationData, 2, 2);
            System.arraycopy(SCP02_CONSTANTS.get(p), 0, derivationData, 0, 2);
            cipher.init(Cipher.ENCRYPT_MODE, cardKey.getKeyAs(Type.DES3), GPCrypto.iv_null_8);
            return new GPKey(cipher.doFinal(derivationData), Type.DES3);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("Session keys calculation failed.", e);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Session keys calculation failed.", e);
        }
    }

    private GPKey deriveSessionKeySCP03(GPKey cardKey, KeyPurpose p, byte[] host_challenge, byte[] card_challenge) {
        if (p == KeyPurpose.DEK) {
            return cardKey;
        }
        byte[] context = GPUtils.concatenate(host_challenge, card_challenge);
        byte[] kdf = GPCrypto.scp03_kdf(cardKey, SCP03_CONSTANTS.get(p), context, cardKey.getLength() * 8);
        return new GPKey(kdf, Type.AES);
    }

    // Return true, if we can handle this card.
    @Override
    public boolean init(byte[] atr, byte[] cplc, byte[] kinfo) {
        logger.debug("Card keys: {}", cardKeys.toString());
        return true;
    }

    @Override
    public void calculate(int scp, byte[] kdd, byte[] host_challenge, byte[] card_challenge, byte[] ssc) throws GPException {
        // Check for arguments
        if (scp == 1 || scp == 3) {
            if (host_challenge == null || card_challenge == null) {
                throw new IllegalArgumentException("SCP0" + scp + " requires host challenge and card challenge");
            }
        } else if (scp == 2) {
            if (ssc == null) {
                throw new IllegalArgumentException("SCP02 requires sequence");
            }
        } else {
            throw new IllegalArgumentException("Don't know how to handle SCP0" + scp);
        }

        logger.debug("Card keys: {}", cardKeys.toString());

        // Calculate per-card keys from master key(s), if needed
        if (diversifier != null) {
            for (Map.Entry<KeyPurpose, GPKey> e : cardKeys.entrySet()) {
                cardKeys.put(e.getKey(), diversify(e.getValue(), e.getKey(), kdd, diversifier));
            }
            logger.trace("Derived per-card keys: {}", cardKeys.toString());
        }

        // Calculate session keys
        for (Map.Entry<KeyPurpose, GPKey> e : cardKeys.entrySet()) {
            if (scp == 1) {
                sessionKeys.put(e.getKey(), deriveSessionKeySCP01(e.getValue(), e.getKey(), host_challenge, card_challenge));
            } else if (scp == 2) {
                sessionKeys.put(e.getKey(), deriveSessionKeySCP02(e.getValue(), e.getKey(), ssc));
            } else if (scp == 3) {
                sessionKeys.put(e.getKey(), deriveSessionKeySCP03(e.getValue(), e.getKey(), host_challenge, card_challenge));
                // Also make a RMAC key
                if (e.getKey() == KeyPurpose.MAC) {
                    sessionKeys.put(KeyPurpose.RMAC, deriveSessionKeySCP03(e.getValue(), KeyPurpose.RMAC, host_challenge, card_challenge));
                }
            }
        }
        logger.trace("Session keys: {}", sessionKeys.toString());
    }

    // Returns the key for the purpose for this session
    @Override
    public GPKey getKeyFor(KeyPurpose p) {
        return sessionKeys.get(p);
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
        VISA2, EMV, KDF3
    }
}
