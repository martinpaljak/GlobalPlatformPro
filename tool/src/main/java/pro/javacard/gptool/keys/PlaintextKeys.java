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
package pro.javacard.gptool.keys;

import apdu4j.core.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.*;

import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static pro.javacard.gp.GPSecureChannelVersion.SCP.*;

// Handles plaintext card keys.
// Supports diversification of card keys with a few known algorithms.
public class PlaintextKeys extends GPCardKeys {
    private static final Logger logger = LoggerFactory.getLogger(PlaintextKeys.class);

    // After diversify() we know for which protocol we have keys for, unless known before
    private static final byte[] defaultKeyBytes = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");

    public static byte[] DEFAULT_KEY() {
        return defaultKeyBytes.clone();
    }

    // Derivation constants for session keys
    public static final Map<KeyPurpose, byte[]> SCP02_CONSTANTS;
    public static final Map<KeyPurpose, Byte> SCP03_CONSTANTS;

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
    }

    public static final Map<String, String> kdf_templates;

    static {
        HashMap<String, String> kdfs = new HashMap<>();
        kdfs.put("emv", "$4 $5 $6 $7 $8 $9 0xF0 $k $4 $5 $6 $7 $8 $9 0x0F $k");
        kdfs.put("visa2", "$0 $1 $4 $5 $6 $7 0xF0 $k $0 $1 $4 $5 $6 $7 0x0F $k");
        kdfs.put("visa", "$0 $1 $2 $3 $8 $9 0xF0 $k $0 $1 $2 $3 $8 $9 0x0F $k");
        kdfs.put("kdf3", "$_ 0x00 0x00 0x00 $k 0x00 $0 $1 $2 $3 $4 $5 $6 $7 $8 $9");
        kdf_templates = Collections.unmodifiableMap(kdfs);
    }

    // If diverisification is to be used
    private String kdf_template;

    public String getTemplate() {
        return kdf_template;
    }

    // Keyset version
    private int version = 0x00;

    // Holds the unmodified master key
    private byte[] masterKey;

    // Holds card-specific keys. They shall be diversified in-place, as needed
    private HashMap<KeyPurpose, byte[]> cardKeys = new HashMap<>();

    private PlaintextKeys(byte[] master, String d) {
        this(master, master, master, d);
        masterKey = master.clone();
    }

    private PlaintextKeys(byte[] enc, byte[] mac, byte[] dek, String d) {
        cardKeys.put(KeyPurpose.ENC, enc.clone());
        cardKeys.put(KeyPurpose.MAC, mac.clone());
        cardKeys.put(KeyPurpose.DEK, dek.clone());
        kdf_template = d;
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

    public static Optional<PlaintextKeys> fromBytes(byte[] enc, byte[] mac, byte[] dek, byte[] mk, String kdf, byte[] kdd, int ver) {
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
                String kdf = kdf_templates.getOrDefault(div, div);
                logger.warn("Different keys and using derivation, is this right?");
                keys.setDiversifier(kdf);
            }
            return Optional.of(keys);
        } else if (mk != null) {
            logger.trace("Using a master key");
            byte[] master = validateKey(HexUtils.stringToBin(mk));
            PlaintextKeys keys = PlaintextKeys.fromMasterKey(master);
            if (div != null) {
                keys.setDiversifier(div);
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
        if (div != null) {
            div = kdf_templates.getOrDefault(div, div);
        }
        String kdd = env.get(prefix + "_KDD");
        String ver = env.get(prefix + "_VER");
        Optional<PlaintextKeys> r = fromStrings(enc, mac, dek, mk, div, kdd, ver);
        if (r.isPresent()) {
            logger.debug("Got keys from environment, prefix=" + prefix);
        }
        return r;
    }

    public static PlaintextKeys fromMasterKey(byte[] master) {
        return new PlaintextKeys(master, null);
    }

    public static PlaintextKeys fromMasterKey(byte[] master, String kdf) {
        return new PlaintextKeys(master, kdf);
    }

    public static PlaintextKeys defaultKey() {
        return new PlaintextKeys(defaultKeyBytes, null);
    }

    public static PlaintextKeys fromKeys(byte[] enc, byte[] mac, byte[] dek) {
        return new PlaintextKeys(enc, mac, dek, null);
    }

    byte[] diversify(byte[] k, KeyPurpose usage, byte[] kdd, String kdf) throws GPException {
        String template = kdf_template_expand(kdf, kdd, usage.getValue());
        try {
            final byte[] kv;
            if (scp == SCP03) {
                template = kdf_template_bitlength(template, k.length * 8);

                byte[] a = kdf_template_finalize(kdf_template_blocka(template));
                byte[] b = kdf_template_finalize(kdf_template_blockb(template));
                return GPCrypto.scp03_kdf(k, a, b, k.length);
            } else {
                kv = kdf_template_finalize(template);
                return GPCrypto.des3_ecb(kv, k);
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("KDF failed", e);
        }
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
            return GPCrypto.des3_ecb(data, sdek);
        } else if (scp == SCP01) {
            return GPCrypto.des3_ecb(data, cardKeys.get(KeyPurpose.DEK));
        } else if (scp == SCP03) {
            return GPCrypto.aes_cbc(data, cardKeys.get(KeyPurpose.DEK), new byte[16]);
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
                return GPCrypto.des3_ecb(other.cardKeys.get(p), cardKeys.get(KeyPurpose.DEK));
            case SCP02:
                byte[] sdek = deriveSessionKeySCP02(cardKeys.get(KeyPurpose.DEK), KeyPurpose.DEK, sessionContext);
                logger.debug("Encrypting {} value (KCV={}) with S-DEK (KCV={})", p, HexUtils.bin2hex(other.kcv(p)), HexUtils.bin2hex(GPCrypto.kcv_3des(sdek)));
                return GPCrypto.des3_ecb(other.cardKeys.get(p), sdek);
            case SCP03:
                logger.debug("Encrypting {} value (KCV={}) with DEK (KCV={})", p, HexUtils.bin2hex(other.kcv(p)), HexUtils.bin2hex(kcv(KeyPurpose.DEK)));
                byte[] otherkey = other.cardKeys.get(p);
                // Pad with random
                int n = otherkey.length % 16 + 1;
                byte[] plaintext = GPCrypto.random(n * otherkey.length);
                System.arraycopy(otherkey, 0, plaintext, 0, otherkey.length);
                // encrypt
                return GPCrypto.aes_cbc(plaintext, cardKeys.get(KeyPurpose.DEK), new byte[16]);
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
                throw new IllegalStateException("Unknown SCP");
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

        if (p == KeyPurpose.RMAC)
            return null;

        byte[] derivationData = new byte[16];
        System.arraycopy(kdd, 12, derivationData, 0, 4);
        System.arraycopy(kdd, 0, derivationData, 4, 4);
        System.arraycopy(kdd, 8, derivationData, 8, 4);
        System.arraycopy(kdd, 4, derivationData, 12, 4);

        try {
            return GPCrypto.des3_ecb(derivationData, cardKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("Can not calculate session keys", e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Session key calculation failed", e);
        }
    }

    private byte[] deriveSessionKeySCP02(byte[] cardKey, KeyPurpose p, byte[] sequence) {
        try {
            byte[] derivationData = new byte[16];
            // constant(2) | counter(2) | 0x00(12)
            System.arraycopy(SCP02_CONSTANTS.get(p), 0, derivationData, 0, 2);
            System.arraycopy(sequence, 0, derivationData, 2, 2);
            return GPCrypto.des3_cbc(derivationData, cardKey, new byte[8]);
        } catch (GeneralSecurityException e) {
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
        if (kdf_template == null)
            return this;

        logger.debug("KDF: applying '{}' to {} KDD {}", kdf_template, scp, HexUtils.bin2hex(kdd));

        // Calculate per-card keys from master key(s), if needed
        for (Map.Entry<KeyPurpose, byte[]> e : cardKeys.entrySet()) {
            cardKeys.put(e.getKey(), diversify(e.getValue(), e.getKey(), kdd, kdf_template));
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

    public void setDiversifier(String template) {
        if (this.kdf_template != null)
            throw new IllegalStateException("KDF already set");
        this.kdf_template = template;
    }

    @Override
    public byte[] scp3_kdf(KeyPurpose purpose, byte[] a, byte[] b, int bytes) {
        return GPCrypto.scp03_kdf(cardKeys.get(purpose), a, b, bytes);
    }

    static String kdf_template_expand(String template, byte[] kdd, byte keytype) {
        // Make everything lower case
        template = template.toLowerCase(Locale.ENGLISH);
        // Remove spaces
        template = template.replace(" ", "");
        // Remove hex indicators
        template = template.replace("0x", "");

        // replace $0..$f - KDD data
        for (int i = 0; i < kdd.length; i++) {
            template = template.replace(String.format("$%x", i), String.format("%02x", kdd[i]));
        }
        // replace $k - key type
        template = template.replace("$k", String.format("%02x", keytype));

        // $_ and $l$l will be replaced in KDF3 code.
        return template;
    }

    static String kdf_template_bitlength(String template, int bits) {
        return template.replace("$l$l", String.format("%04x", bits));
    }

    static String kdf_template_blocka(String template) {
        int pos = template.indexOf("$_");
        if (pos == -1)
            throw new IllegalArgumentException("Invalid template (missing '$_'): " + template);
        return template.substring(0, pos);
    }

    static String kdf_template_blockb(String template) {
        int pos = template.indexOf("$_");
        if (pos == -1)
            throw new IllegalArgumentException("Invalid template (missing '$_'): " + template);
        return template.substring(pos + 2);
    }

    static byte[] kdf_template_finalize(String template) throws IllegalArgumentException {
        if (template.contains("$"))
            throw new IllegalArgumentException("Invalid template (still includes '$'): " + template);
        return HexUtils.hex2bin(template);
    }
}
