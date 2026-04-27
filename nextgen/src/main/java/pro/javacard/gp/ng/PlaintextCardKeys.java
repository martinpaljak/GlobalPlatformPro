// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.core.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPSecureChannelVersion.SCP;

import java.security.GeneralSecurityException;
import java.util.*;

import static pro.javacard.gp.GPSecureChannelVersion.SCP.*;

// Immutable plaintext card keys. Each mutation (diversify) returns a new instance.
public final class PlaintextCardKeys implements CardKeys, AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(PlaintextCardKeys.class);

    private static final byte[] DEFAULT_KEY_BYTES = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");

    // SCP02 session key derivation constants
    static final Map<KeyPurpose, byte[]> SCP02_CONSTANTS;
    // SCP03 session key derivation constants (RMAC derived from MAC key, constant 0x07)
    static final byte SCP03_ENC = (byte) 0x04;
    static final byte SCP03_MAC = (byte) 0x06;
    static final byte SCP03_RMAC = (byte) 0x07;

    static {
        var scp2 = new HashMap<KeyPurpose, byte[]>();
        scp2.put(KeyPurpose.MAC, new byte[]{(byte) 0x01, (byte) 0x01});
        scp2.put(KeyPurpose.ENC, new byte[]{(byte) 0x01, (byte) 0x82});
        scp2.put(KeyPurpose.DEK, new byte[]{(byte) 0x01, (byte) 0x81});
        SCP02_CONSTANTS = Collections.unmodifiableMap(scp2);
    }

    // @formatter:off
    public static final Map<String, String> KDF_TEMPLATES = Map.of(
        "emv",   "$4 $5 $6 $7 $8 $9 0xF0 $k $4 $5 $6 $7 $8 $9 0x0F $k",
        "visa2", "$0 $1 $4 $5 $6 $7 0xF0 $k $0 $1 $4 $5 $6 $7 0x0F $k",
        "visa",  "$0 $1 $2 $3 $8 $9 0xF0 $k $0 $1 $2 $3 $8 $9 0x0F $k",
        "kdf3",  "$_ 0x00 0x00 0x00 $k 0x00 $0 $1 $2 $3 $4 $5 $6 $7 $8 $9"
    );
    // @formatter:on

    // All fields final - immutable after construction
    private final SCP scp;
    private final byte[] kdd;
    private final byte[] enc;
    private final byte[] mac;
    private final byte[] dek;
    private final String kdfTemplate;
    private final byte[] masterKey; // null if from individual keys
    private final int version;

    private PlaintextCardKeys(SCP scp, byte[] kdd, byte[] enc, byte[] mac, byte[] dek, String kdfTemplate, byte[] masterKey, int version) {
        this.scp = scp;
        this.kdd = kdd != null ? kdd.clone() : null;
        this.enc = enc.clone();
        this.mac = mac.clone();
        this.dek = dek.clone();
        this.kdfTemplate = kdfTemplate;
        this.masterKey = masterKey != null ? masterKey.clone() : null;
        this.version = version;
    }

    // --- Static factories ---

    public static byte[] defaultKeyBytes() {
        return DEFAULT_KEY_BYTES.clone();
    }

    public static PlaintextCardKeys defaultKey() {
        return new PlaintextCardKeys(null, null, DEFAULT_KEY_BYTES, DEFAULT_KEY_BYTES, DEFAULT_KEY_BYTES, null, null, 0x00);
    }

    public static PlaintextCardKeys fromMasterKey(byte[] master) {
        validateKey(master);
        return new PlaintextCardKeys(null, null, master, master, master, null, master, 0x00);
    }

    public static PlaintextCardKeys fromMasterKey(byte[] master, String kdf) {
        validateKey(master);
        return new PlaintextCardKeys(null, null, master, master, master, kdf, master, 0x00);
    }

    public static PlaintextCardKeys fromKeys(byte[] enc, byte[] mac, byte[] dek) {
        validateKey(enc);
        validateKey(mac);
        validateKey(dek);
        return new PlaintextCardKeys(null, null, enc, mac, dek, null, null, 0x00);
    }

    public static Optional<PlaintextCardKeys> fromEnvironment() {
        return fromEnvironment(System.getenv(), "GP_KEY");
    }

    public static Optional<PlaintextCardKeys> fromEnvironment(Map<String, String> env, String prefix) {
        var encStr = env.get(prefix + "_ENC");
        var macStr = env.get(prefix + "_MAC");
        var dekStr = env.get(prefix + "_DEK");
        var mkStr = env.get(prefix);
        var divStr = env.get(prefix + "_KDF");
        if (divStr != null) {
            divStr = KDF_TEMPLATES.getOrDefault(divStr, divStr);
        }
        var kddStr = env.get(prefix + "_KDD");
        var verStr = env.get(prefix + "_VER");
        return fromStrings(encStr, macStr, dekStr, mkStr, divStr, kddStr, verStr);
    }

    public static Optional<PlaintextCardKeys> fromStrings(String encStr, String macStr, String dekStr, String mkStr, String div, String kddStr,
            String verStr) {
        if ((encStr != null || macStr != null || dekStr != null) && (encStr == null || macStr == null || dekStr == null || mkStr != null)) {
            throw new IllegalArgumentException("Either all or nothing of enc/mac/dek keys must be set, and no mk at the same time!");
        }

        if (encStr != null && macStr != null && dekStr != null) {
            var keys = fromKeys(HexUtils.stringToBin(encStr), HexUtils.stringToBin(macStr), HexUtils.stringToBin(dekStr));
            if (div != null) {
                logger.warn("Different keys and using derivation, is this right?");
                keys = keys.withKdfTemplate(KDF_TEMPLATES.getOrDefault(div, div));
            }
            if (verStr != null) {
                keys = keys.withVersion(parseVersion(verStr));
            }
            return Optional.of(keys);
        } else if (mkStr != null) {
            var master = validateKey(HexUtils.stringToBin(mkStr));
            var kdf = div != null ? KDF_TEMPLATES.getOrDefault(div, div) : null;
            if (kdf == null) {
                logger.warn("Using master key without derivation, is this right?");
            }
            var keys = fromMasterKey(master, kdf);
            if (kddStr != null) {
                keys = keys.withKdd(HexUtils.stringToBin(kddStr));
            }
            if (verStr != null) {
                keys = keys.withVersion(parseVersion(verStr));
            }
            return Optional.of(keys);
        }
        return Optional.empty();
    }

    // --- Immutable "with" builders ---

    public PlaintextCardKeys withVersion(int version) {
        return new PlaintextCardKeys(scp, kdd, enc, mac, dek, kdfTemplate, masterKey, version);
    }

    public PlaintextCardKeys withKdfTemplate(String template) {
        if (kdfTemplate != null) {
            throw new IllegalStateException("KDF already set");
        }
        return new PlaintextCardKeys(scp, kdd, enc, mac, dek, template, masterKey, version);
    }

    public PlaintextCardKeys withKdd(byte[] kdd) {
        return new PlaintextCardKeys(scp, kdd, enc, mac, dek, kdfTemplate, masterKey, version);
    }

    // --- CardKeys interface ---

    @Override
    public CardKeys diversify(SCP scp, byte[] kdd) {
        if (kdd != null && kdd.length > 10) {
            throw new IllegalArgumentException("KDD too long: " + kdd.length);
        }
        if (this.scp != null) {
            throw new IllegalStateException("Keys already diversified!");
        }

        if (kdfTemplate == null) {
            // No KDF - just bind SCP/KDD
            return new PlaintextCardKeys(scp, kdd, enc, mac, dek, null, masterKey, version);
        }

        logger.debug("KDF: applying '{}' to {} KDD {}", kdfTemplate, scp, HexUtils.bin2hex(kdd));
        var dEnc = diversifyKey(enc, KeyPurpose.ENC, kdd, kdfTemplate, scp);
        var dMac = diversifyKey(mac, KeyPurpose.MAC, kdd, kdfTemplate, scp);
        var dDek = diversifyKey(dek, KeyPurpose.DEK, kdd, kdfTemplate, scp);
        return new PlaintextCardKeys(scp, kdd, dEnc, dMac, dDek, null, masterKey, version);
    }

    @Override
    public SessionKeys deriveSession(byte[] sessionContext) {
        requireScp();
        return switch (scp) {
            case SCP01 -> new SessionKeys.SCP01Keys(deriveSessionSCP01(enc, KeyPurpose.ENC, sessionContext),
                    deriveSessionSCP01(mac, KeyPurpose.MAC, sessionContext));
            case SCP02 -> new SessionKeys.SCP02Keys(deriveSessionSCP02(enc, KeyPurpose.ENC, sessionContext),
                    deriveSessionSCP02(mac, KeyPurpose.MAC, sessionContext), deriveSessionSCP02(mac, KeyPurpose.MAC, sessionContext, true));
            case SCP03 -> new SessionKeys.SCP03Keys(GPCrypto.scp03_kdf(enc, SCP03_ENC, sessionContext, enc.length * 8),
                    GPCrypto.scp03_kdf(mac, SCP03_MAC, sessionContext, mac.length * 8),
                    GPCrypto.scp03_kdf(mac, SCP03_RMAC, sessionContext, mac.length * 8));
            default -> throw new IllegalStateException("Unknown SCP: " + scp);
        };
    }

    @Override
    public byte[] encryptDEK(byte[] data, byte[] sessionContext) {
        requireScp();
        try {
            return switch (scp) {
                case SCP01 -> GPCrypto.des3_ecb(data, dek);
                case SCP02 -> {
                    var sdek = deriveSessionSCP02(dek, KeyPurpose.DEK, sessionContext);
                    yield GPCrypto.des3_ecb(data, sdek);
                }
                case SCP03 -> GPCrypto.aes_cbc(data, dek, new byte[16]);
                default -> throw new IllegalStateException("Unknown SCP: " + scp);
            };
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("DEK encryption failed", e);
        }
    }

    @Override
    public byte[] wrapKey(byte[] keyValue, byte[] sessionContext) {
        requireScp();
        try {
            return switch (scp) {
                case SCP01 -> GPCrypto.des3_ecb(keyValue, dek);
                case SCP02 -> {
                    var sdek = deriveSessionSCP02(dek, KeyPurpose.DEK, sessionContext);
                    yield GPCrypto.des3_ecb(keyValue, sdek);
                }
                case SCP03 -> {
                    // Pad with random for AES key wrapping
                    var n = keyValue.length % 16 + 1;
                    var plaintext = GPCrypto.random(n * keyValue.length);
                    System.arraycopy(keyValue, 0, plaintext, 0, keyValue.length);
                    yield GPCrypto.aes_cbc(plaintext, dek, new byte[16]);
                }
                default -> throw new IllegalStateException("Unknown SCP: " + scp);
            };
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Key wrapping failed", e);
        }
    }

    @Override
    public byte[] kdf(KeyPurpose purpose, byte[] a, byte[] b, int bytes) {
        var key = keyFor(purpose);
        return GPCrypto.scp03_kdf(key, a, b, bytes);
    }

    @Override
    public byte[] kcv(KeyPurpose purpose) {
        var key = keyFor(purpose);
        if (scp == SCP03) {
            return GPCrypto.kcv_aes(key);
        } else if (scp == SCP01 || scp == SCP02) {
            return GPCrypto.kcv_3des(key);
        } else {
            // Before diversification, guess from key length
            return key.length > 16 ? GPCrypto.kcv_aes(key) : GPCrypto.kcv_3des(key);
        }
    }

    @Override
    public KeyInfo keyInfo() {
        var type = enc.length > 16 || scp == SCP03 ? KeyInfo.KeyType.AES : KeyInfo.KeyType.DES3;
        return new KeyInfo(version, 0x01, enc.length, type);
    }

    @Override
    public Optional<SCP> scp() {
        return Optional.ofNullable(scp);
    }

    // --- Accessors ---

    public Optional<byte[]> getMasterKey() {
        return Optional.ofNullable(masterKey != null ? masterKey.clone() : null);
    }

    public String getKdfTemplate() {
        return kdfTemplate;
    }

    // Raw key bytes for a purpose - needed by put_keys to read new key values
    public byte[] rawKey(KeyPurpose purpose) {
        return keyFor(purpose).clone();
    }

    @Override
    public void close() {
        Arrays.fill(enc, (byte) 0);
        Arrays.fill(mac, (byte) 0);
        Arrays.fill(dek, (byte) 0);
        if (masterKey != null) {
            Arrays.fill(masterKey, (byte) 0);
        }
    }

    @Override
    public String toString() {
        return "ENC=%s (KCV: %s) MAC=%s (KCV: %s) DEK=%s (KCV: %s) for %s".formatted(HexUtils.bin2hex(enc), HexUtils.bin2hex(kcv(KeyPurpose.ENC)),
                HexUtils.bin2hex(mac), HexUtils.bin2hex(kcv(KeyPurpose.MAC)), HexUtils.bin2hex(dek), HexUtils.bin2hex(kcv(KeyPurpose.DEK)), scp);
    }

    // --- Private helpers ---

    private byte[] keyFor(KeyPurpose purpose) {
        return switch (purpose) {
            case ENC -> enc;
            case MAC -> mac;
            case DEK -> dek;
        };
    }

    private void requireScp() {
        if (scp == null) {
            throw new IllegalStateException("Keys not diversified - call diversify() first");
        }
    }

    private static byte[] validateKey(byte[] k) {
        if (k.length != 16 && k.length != 24 && k.length != 32) {
            throw new IllegalArgumentException("Invalid key length %d: %s".formatted(k.length, HexUtils.bin2hex(k)));
        }
        return k;
    }

    private static int parseVersion(String ver) {
        if (ver.toLowerCase(Locale.ROOT).startsWith("0x")) {
            return Integer.parseInt(ver.substring(2), 16);
        }
        return Integer.parseInt(ver);
    }

    // --- SCP01 session key derivation ---
    private static byte[] deriveSessionSCP01(byte[] cardKey, KeyPurpose p, byte[] kdd) {
        if (p == KeyPurpose.DEK) {
            return cardKey.clone();
        }
        // Permute the 16-byte context: [12:16][0:4][8:12][4:8]
        var derivationData = new byte[16];
        System.arraycopy(kdd, 12, derivationData, 0, 4);
        System.arraycopy(kdd, 0, derivationData, 4, 4);
        System.arraycopy(kdd, 8, derivationData, 8, 4);
        System.arraycopy(kdd, 4, derivationData, 12, 4);
        try {
            return GPCrypto.des3_ecb(derivationData, cardKey);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("SCP01 session key derivation failed", e);
        }
    }

    // --- SCP02 session key derivation ---
    private static byte[] deriveSessionSCP02(byte[] cardKey, KeyPurpose p, byte[] sequence) {
        return deriveSessionSCP02(cardKey, p, sequence, false);
    }

    // SCP02 RMAC constant (0x0102) - not in SCP02_CONSTANTS since KeyPurpose has no RMAC
    private static final byte[] SCP02_RMAC_CONSTANT = new byte[]{(byte) 0x01, (byte) 0x02};

    private static byte[] deriveSessionSCP02(byte[] cardKey, KeyPurpose p, byte[] sequence, boolean rmac) {
        try {
            var derivationData = new byte[16];
            var constant = rmac ? SCP02_RMAC_CONSTANT : SCP02_CONSTANTS.get(p);
            System.arraycopy(constant, 0, derivationData, 0, 2);
            System.arraycopy(sequence, 0, derivationData, 2, 2);
            return GPCrypto.des3_cbc(derivationData, cardKey, new byte[8]);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("SCP02 session key derivation failed", e);
        }
    }

    // --- Key diversification ---
    private static byte[] diversifyKey(byte[] key, KeyPurpose purpose, byte[] kdd, String template, SCP scp) {
        var expanded = kdfTemplateExpand(template, kdd, purpose.getValue());
        try {
            if (scp == SCP03) {
                expanded = kdfTemplateBitlength(expanded, key.length * 8);
                var a = kdfTemplateFinalize(kdfTemplateBlockA(expanded));
                var b = kdfTemplateFinalize(kdfTemplateBlockB(expanded));
                return GPCrypto.scp03_kdf(key, a, b, key.length);
            } else {
                var kv = kdfTemplateFinalize(expanded);
                return GPCrypto.des3_ecb(kv, key);
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("KDF failed", e);
        }
    }

    // --- KDF template processing ---
    static String kdfTemplateExpand(String template, byte[] kdd, byte keytype) {
        template = template.toLowerCase(Locale.ENGLISH).replace(" ", "").replace("0x", "");
        for (var i = 0; i < kdd.length; i++) {
            template = template.replace("$%x".formatted(i), "%02x".formatted(kdd[i]));
        }
        return template.replace("$k", "%02x".formatted(keytype));
    }

    static String kdfTemplateBitlength(String template, int bits) {
        return template.replace("$l$l", "%04x".formatted(bits));
    }

    static String kdfTemplateBlockA(String template) {
        var pos = template.indexOf("$_");
        if (pos == -1) {
            throw new IllegalArgumentException("Invalid template (missing '$_'): " + template);
        }
        return template.substring(0, pos);
    }

    static String kdfTemplateBlockB(String template) {
        var pos = template.indexOf("$_");
        if (pos == -1) {
            throw new IllegalArgumentException("Invalid template (missing '$_'): " + template);
        }
        return template.substring(pos + 2);
    }

    static byte[] kdfTemplateFinalize(String template) {
        if (template.contains("$")) {
            throw new IllegalArgumentException("Invalid template (still includes '$'): " + template);
        }
        return HexUtils.hex2bin(template);
    }
}
