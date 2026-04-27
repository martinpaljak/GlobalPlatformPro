// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.apdulette.KitchenDisaster;
import apdu4j.apdulette.Recipe;
import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import apdu4j.prefs.Preference;
import apdu4j.prefs.Preferences;
import pro.javacard.capfile.AID;
import pro.javacard.gp.DMTokenizer;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.GPUtils;
import pro.javacard.gp.ReceiptVerifier;
import pro.javacard.gp.data.BitField;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVParseException;
import pro.javacard.tlv.Tag;

import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.emv.DGIData;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;

import java.io.ByteArrayOutputStream;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import static apdu4j.apdulette.Cookbook.*;

// Composable GP card interaction recipes, executed by a Chef.
// IMPORTANT: this class MUST remain pure - only data and Recipe composition.
// Never import BIBO, never create a Chef, never call transceive/cook here.
// All recipes are pure descriptions of what to do; the caller's Chef executes them.
public final class GlobalPlatformCookbook {
    private GlobalPlatformCookbook() {}

    // GP constants
    static final int CLA_GP = 0x80;
    static final int CLA_MAC = 0x84;
    static final int INS_DELETE = 0xE4;
    static final int INS_INSTALL = 0xE6;
    static final int INS_LOAD = 0xE8;
    static final int INS_GET_DATA = 0xCA;
    static final int INS_GET_STATUS = 0xF2;
    static final int INS_SET_STATUS = 0xF0;
    static final int INS_STORE_DATA = 0xE2;
    static final int INS_INITIALIZE_UPDATE = 0x50;
    static final int INS_EXTERNAL_AUTHENTICATE = 0x82;

    // Well-known AIDs
    static final byte[] DEFAULT_ISD = HexUtils.hex2bin("A000000151000000");
    static final byte[] JCOP_IDENTIFY = HexUtils.hex2bin("A000000167413000FF");

    // GP CommandAPDU: CLA=80, Le=256
    static CommandAPDU cmd(final int ins, final int p1, final int p2) {
        return new CommandAPDU(CLA_GP, ins, p1, p2, 256);
    }

    static CommandAPDU cmd(final int ins, final int p1, final int p2, final byte[] data) {
        return new CommandAPDU(CLA_GP, ins, p1, p2, data, 256);
    }

    // GP recipe shorthand: cmd + expect 9000
    static Recipe<ResponseAPDU> gp(final int ins, final int p1, final int p2, final byte[] data) {
        return send(cmd(ins, p1, p2, data));
    }

    // GP recipe with optional DM token and receipt verification at prepare-time
    static Recipe<ResponseAPDU> gp_dm(final int ins, final int p1, final int p2, final byte[] data) {
        return gp_dm(ins, p1, p2, data, null);
    }

    static Recipe<ResponseAPDU> gp_dm(final int ins, final int p1, final int p2, final byte[] data,
            final byte[] receiptContext) {
        return deferred(prefs -> {
            var apdu = cmd(ins, p1, p2, data);
            var tok = prefs.valueOf(DM_TOKENIZER);
            if (tok.isPresent()) {
                apdu = tok.get().tokenize(apdu);
            }
            var recipe = send(apdu);
            var verifier = prefs.valueOf(RECEIPT_VERIFIER);
            if (verifier.isPresent() && receiptContext != null) {
                final var v = verifier.get();
                final var ctx = receiptContext;
                recipe = recipe.consume(r -> v.check(r, ctx));
            }
            return recipe;
        });
    }

    // GP chunked batch: split by BLOCK_SIZE, last-block bit in P1, sequential P2
    static Recipe<ResponseAPDU> chunked(final int ins, final int p1, final byte[] data) {
        return deferred(prefs -> {
            final var blocks = GPUtils.splitArray(data, prefs.get(BLOCK_SIZE));
            final var commands = new ArrayList<CommandAPDU>(blocks.size());
            for (var i = 0; i < blocks.size(); i++) {
                final int v = i == blocks.size() - 1 ? p1 | 0x80 : p1 & ~0x80;
                commands.add(cmd(ins, v, i, blocks.get(i)));
            }
            return send(commands, 0x9000);
        });
    }

    // === Preference keys: card behavior (replaces GPCardProfile) ===

    // GET STATUS response format: true = TLV tags (P2=0x02), false = legacy (P2=0x00)
    public static final Preference.Default<Boolean> STATUS_USE_TAGS =
            Preference.of("gp.status.use.tags", Boolean.class, true, false);

    // Whether to query load files with modules (P1=0x10) in addition to plain load files (P1=0x20)
    public static final Preference.Default<Boolean> STATUS_REPORT_MODULES =
            Preference.of("gp.status.report.modules", Boolean.class, true, false);

    // Whether INSTALL [for extradition] uses old-style fixed parameters (C90145)
    // instead of modern TLV tag 0x81 for secure channel specification
    public static final Preference.Default<Boolean> INSTALL_OLD_SSD_PARAMS =
            Preference.of("gp.install.old.ssd.params", Boolean.class, false, false);

    // SCP03: some cards only increment encryption counter when data is present,
    // violating GP 2.2 Amendment D v1.1.1 section 6.2.6 which mandates increment
    // for every C-APDU. Enable this to match those broken implementations.
    public static final Preference.Default<Boolean> SCP03_BUGGY_COUNTER =
            Preference.of("gp.scp03.buggy.counter", Boolean.class, false, false);

    // Hash algorithm for Load File Data Block Hash in INSTALL [for load].
    // JCA algorithm name: SHA-1, SHA-256, SHA-384, SHA-512
    public static final Preference.Default<String> LOAD_HASH =
            Preference.of("gp.load.hash", String.class, "SHA-256", false);

    // === Named presets (replacing GPCardProfile) ===

    // Modern cards: TLV status, module reporting, modern SSD params, SHA-256 load hash
    public static final Preferences PRESET_DEFAULT = new Preferences();

    // Legacy cards: no TLV status, no module reporting, old-style SSD params, SHA-1 load hash
    public static final Preferences PRESET_OLD = new Preferences()
            .with(STATUS_USE_TAGS, false)
            .with(STATUS_REPORT_MODULES, false)
            .with(INSTALL_OLD_SSD_PARAMS, true)
            .with(LOAD_HASH, "SHA-1");

    public static final Map<String, Preferences> PRESETS = Map.of(
            "default", PRESET_DEFAULT,
            "old", PRESET_OLD
    );

    // === Preference keys: discovery results ===

    public static final Preference.Parameter<AID> ISD_AID =
            Preference.parameter("gp.isd.aid", AID.class, true);

    public static final Preference.Default<Integer> BLOCK_SIZE =
            Preference.of("gp.block.size", Integer.class, 255, false);

    public static final Preference.Parameter<GPSecureChannelVersion> SCP_VERSION =
            Preference.parameter("gp.scp.version", GPSecureChannelVersion.class, true);

    public static final Preference.Parameter<String> GP_VERSION =
            Preference.parameter("gp.version", String.class, true);

    // GET DATA results (raw bytes)
    public static final Preference.Parameter<byte[]> CPLC =
            Preference.parameter("gp.cplc", byte[].class, true);

    public static final Preference.Parameter<byte[]> IIN =
            Preference.parameter("gp.iin", byte[].class, true);

    public static final Preference.Parameter<byte[]> CIN =
            Preference.parameter("gp.cin", byte[].class, true);

    public static final Preference.Parameter<byte[]> KDD =
            Preference.parameter("gp.kdd", byte[].class, true);

    public static final Preference.Parameter<byte[]> SSC =
            Preference.parameter("gp.ssc", byte[].class, true);

    public static final Preference.Parameter<byte[]> CARD_DATA =
            Preference.parameter("gp.card.data", byte[].class, true);

    public static final Preference.Parameter<byte[]> CARD_CAPABILITIES =
            Preference.parameter("gp.card.capabilities", byte[].class, true);

    public static final Preference.Parameter<byte[]> KEY_INFO =
            Preference.parameter("gp.key.info", byte[].class, true);

    // Session context for DEK encryption (populated after open_secure_channel)
    public static final Preference.Parameter<byte[]> SESSION_CONTEXT =
            Preference.parameter("gp.session.context", byte[].class, false);

    // === Preference keys: CLI/operational ===

    // Force 16-byte host challenge in INITIALIZE UPDATE (S16 mode)
    // When false (default), 8-byte with automatic retry on 0x6700
    public static final Preference.Default<Boolean> FORCE_S16 =
            Preference.of("gp.scp.force.s16", Boolean.class, false, false);

    // Delegated management tokenizer (optional, for --dm-key/--dm-token)
    public static final Preference.Parameter<DMTokenizer> DM_TOKENIZER =
            Preference.parameter("gp.dm.tokenizer", DMTokenizer.class, false);

    // Receipt verifier (optional, for --receipt-key)
    public static final Preference.Parameter<ReceiptVerifier> RECEIPT_VERIFIER =
            Preference.parameter("gp.receipt.verifier", ReceiptVerifier.class, false);

    // === Building blocks ===

    // SELECT (GPC 2.3.1 11.9) - empty AID, accept 9000 or 6283 (locked)
    public static Recipe<ResponseAPDU> select_default() {
        return send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, 256), expect(0x9000, 0x6283));
    }

    // SELECT (GPC 2.3.1 11.9) - by AID, accept 9000 or 6283
    public static Recipe<ResponseAPDU> select_aid(final byte[] aid) {
        return send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid, 256), expect(0x9000, 0x6283));
    }

    // SELECT for JCOP identification - fails recipe if card is unfused
    public static Recipe<ResponseAPDU> check_jcop_unfused() {
        return send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, JCOP_IDENTIFY, 256))
                .then(r -> {
                    if (r.getData().length > 15 && r.getData()[14] == 0x00) {
                        return Recipe.<ResponseAPDU>error("Unfused JCOP detected");
                    }
                    return Recipe.premade(r);
                });
    }

    // Try AIDs from list, chained with orElse fallback
    public static Recipe<ResponseAPDU> try_aids(final List<AID> aids) {
        if (aids.isEmpty()) {
            return Recipe.error("No ISD found");
        }
        return firstOf(aids.stream().map(a -> select_aid(a.getBytes())).toList());
    }

    // GET DATA (GPC 2.3.1 11.3) with optional CLA fallback - returns Optional.empty() on any failure
    public static Recipe<Optional<byte[]>> get_data(final int p1, final int p2, final boolean failsafe) {
        final var primary = data(cmd(INS_GET_DATA, p1, p2),
                GlobalPlatformCookbook::unwrap_tlv);
        if (failsafe) {
            return primary
                    .orElse(data(new CommandAPDU(0x00, INS_GET_DATA, p1, p2, 256),
                            GlobalPlatformCookbook::unwrap_tlv))
                    .optional();
        }
        return primary.optional();
    }

    // Strip outer TLV tag-length, return just the value
    public static byte[] unwrap_tlv(final byte[] data) {
        final var tlvs = TLV.parse(data);
        if (tlvs.isEmpty()) {
            return data;
        }
        return tlvs.getFirst().value();
    }

    // Fold a GET DATA result into existing Preferences
    public static Recipe<Preferences> fold_data(Preferences prefs, Preference.Parameter<byte[]> key, int p1, int p2, boolean failsafe) {
        return get_data(p1, p2, failsafe)
                .map(opt -> opt.map(v -> prefs.with(key, v)).orElse(prefs));
    }

    // Parse SELECT FCI response (GPC 2.3.1 11.9, Table 11-49)
    public static Preferences parse_fci(final ResponseAPDU response) {
        var prefs = new Preferences();
        final var data = response.getData();
        if (data.length == 0) {
            return prefs;
        }

        // TLVParseException propagates - broken FCI after successful SELECT is a real error
        final var tlvs = TLV.parse(data);

        final var fciOpt = TLV.find(tlvs, Tag.ber(0x6F));
        if (fciOpt.isEmpty()) {
            return prefs;
        }
        final var fci = fciOpt.get();

        // AID from tag 84
        final var aidTag = fci.find(Tag.ber(0x84));
        if (aidTag != null && aidTag.value().length > 0) {
            prefs = prefs.with(ISD_AID, new AID(aidTag.value()));
        }

        final var prop = fci.find(Tag.ber(0xA5));
        if (prop == null) {
            return prefs;
        }

        // Card Recognition Data (73)
        final var isdd = prop.find(Tag.ber(0x73));
        if (isdd != null) {
            prefs = parse_card_recognition_data(prefs, isdd);
        }

        // Block size from tag 9F65
        final var maxbs = prop.find(Tag.ber(0x9F, 0x65));
        if (maxbs != null && maxbs.value().length > 0 && maxbs.value().length <= 2) {
            var bs = 0;
            for (byte b : maxbs.value()) {
                bs = (bs << 8) | (b & 0xFF);
            }
            if (bs > 0) {
                prefs = prefs.with(BLOCK_SIZE, bs);
            }
        }

        return prefs;
    }

    // Parse Card Recognition Data (GPC 2.3.1 H.2, tag 73)
    public static Preferences parse_card_recognition_data(Preferences prefs, TLV isdd) {
        // GP version from tag 60 -> 06
        final var verTag = isdd.find(Tag.ber(0x60));
        if (verTag != null) {
            final var verOid = verTag.find(Tag.ber(0x06));
            if (verOid != null) {
                prefs = prefs.with(GP_VERSION, GPData.oid2version(verOid.value()));
            }
        }

        // SCP version from tag 64 -> 06
        final var scpTag = isdd.find(Tag.ber(0x64));
        if (scpTag != null) {
            final var scpOid = scpTag.find(Tag.ber(0x06));
            if (scpOid != null && scpOid.value().length == 9) {
                final var d = scpOid.value();
                prefs = prefs.with(SCP_VERSION, GPSecureChannelVersion.valueOf(d[7] & 0xFF, d[8] & 0xFF));
            }
        }

        return prefs;
    }

    // === Composed recipes ===

    // Locate ISD with fallbacks -> Preferences from FCI
    public static Recipe<Preferences> locate_isd(final List<AID> extraAIDs) {
        return select_default()
                .recover(err -> switch (err.sw()) {
                    case 0x6A82 -> check_jcop_unfused().and(try_aids(extraAIDs));
                    case 0x6A87 -> select_aid(DEFAULT_ISD);
                    default -> Recipe.error(err.message() + " (SW: %04X)".formatted(err.sw()));
                })
                .map(GlobalPlatformCookbook::parse_fci);
    }

    // Full discovery: locate ISD + all unauthenticated GET DATA
    public static Recipe<Preferences> discover(final List<AID> extraAIDs) {
        return locate_isd(extraAIDs)
                .then(p -> fold_data(p, CPLC, 0x9F, 0x7F, true))
                .then(p -> fold_data(p, IIN, 0x00, 0x42, false))
                .then(p -> fold_data(p, CIN, 0x00, 0x45, false))
                .then(p -> fold_data(p, KDD, 0x00, 0xCF, false))
                .then(p -> fold_data(p, SSC, 0x00, 0xC1, false))
                .then(p -> fold_data(p, CARD_DATA, 0x00, 0x66, false))
                .then(p -> fold_data(p, CARD_CAPABILITIES, 0x00, 0x67, false))
                .then(p -> fold_data(p, KEY_INFO, 0x00, 0xE0, false));
    }

    // === GET STATUS recipes ===

    static final byte[] GET_STATUS_FILTER = new byte[]{0x4F, 0x00};

    // GET STATUS (GPC 2.3.1 11.4) with 6310 continuation
    // Reads STATUS_USE_TAGS at prepare-time: P2=0x02 (TLV, Table 11-39) or P2=0x00 (legacy)
    public static Recipe<byte[]> get_status(final int p1) {
        return deferred(prefs -> {
            final var p2 = prefs.get(STATUS_USE_TAGS) ? 0x02 : 0x00;
            final var alsoDone = p1 == 0x10
                    ? List.of(0x6A88, 0x6A86, 0x6A81)
                    : List.of(0x6A88);
            return gather(
                    cmd(INS_GET_STATUS, p1, p2, GET_STATUS_FILTER),
                    0x6310,
                    r -> cmd(INS_GET_STATUS, p1, p2 | 0x01, GET_STATUS_FILTER),
                    0x9000,
                    "GET STATUS failed",
                    alsoDone);
        });
    }

    // GET STATUS + parse entries of the given kind - reusable building block
    public static Recipe<List<GPRegistryEntryNG>> get_status_parsed(final int p1, final GPRegistryEntryNG.Kind kind) {
        return get_status(p1).map(data -> GPRegistryNG.parseTLV(data, kind));
    }

    // Full registry: ISD + APPs + packages
    // Reads STATUS_REPORT_MODULES preference to conditionally include P1=0x10 query
    public static Recipe<GPRegistryNG> get_registry() {
        return deferred(prefs -> {
            var recipe = get_status_parsed(0x80, GPRegistryEntryNG.Kind.IssuerSecurityDomain)
                    .map(GPRegistryNG::new)
                    .then(reg -> get_status_parsed(0x40, GPRegistryEntryNG.Kind.Application).map(reg::merge));
            if (prefs.get(STATUS_REPORT_MODULES)) {
                recipe = recipe.then(reg -> get_status_parsed(0x10, GPRegistryEntryNG.Kind.ExecutableLoadFile).map(reg::merge));
            }
            return recipe
                    .then(reg -> get_status_parsed(0x20, GPRegistryEntryNG.Kind.ExecutableLoadFile).map(reg::merge));
        });
    }

    // === Authentication utilities ===

    // Normalize security level (GPC AmdD 7.1.2.1): implied modes (RENC -> ENC+RMAC, ENC/RMAC -> MAC)
    public static EnumSet<GPSession.APDUMode> normalize(final EnumSet<GPSession.APDUMode> securityLevel) {
        final var sl = EnumSet.copyOf(securityLevel);
        if (sl.contains(GPSession.APDUMode.RENC)) {
            sl.add(GPSession.APDUMode.ENC);
            sl.add(GPSession.APDUMode.RMAC);
        }
        if (sl.contains(GPSession.APDUMode.ENC) || sl.contains(GPSession.APDUMode.RMAC)) {
            sl.add(GPSession.APDUMode.MAC);
        }
        return sl;
    }

    // Map SCP id byte to enum
    public static GPSecureChannelVersion.SCP scp_version(final int scp) {
        return switch (scp) {
            case 0x01 -> GPSecureChannelVersion.SCP.SCP01;
            case 0x02 -> GPSecureChannelVersion.SCP.SCP02;
            case 0x03 -> GPSecureChannelVersion.SCP.SCP03;
            default -> throw new GPException("Unsupported SCP: " + scp);
        };
    }

    // === Authentication recipes ===

    // INITIALIZE UPDATE (GPC 2.3.1 11.1.3) - establish SCP session key negotiation
    public static Recipe<InitUpdateResponse> init_update(final int keyVersion, final int keyId, final byte[] hostChallenge) {
        final var hc = hostChallenge != null ? hostChallenge.clone() : GPCrypto.random(8);
        return send(cmd(INS_INITIALIZE_UPDATE, keyVersion, keyId, hc), any())
                .then(r -> {
                    if (r.getSW() == 0x6700 && hc.length == 8) {
                        // Retry with 16-byte challenge (S16 mode)
                        final var hc16 = GPCrypto.random(16);
                        return send(cmd(INS_INITIALIZE_UPDATE, keyVersion, keyId, hc16))
                                .map(r2 -> InitUpdateResponse.parse(r2.getData(), hc16));
                    }
                    if (r.getSW() == 0x6982 || r.getSW() == 0x6983) {
                        throw new KitchenDisaster("INITIALIZE UPDATE failed, card locked?");
                    }
                    if (r.getSW() != 0x9000) {
                        return Recipe.error("INITIALIZE UPDATE failed (SW: %04X)".formatted(r.getSW()));
                    }
                    return Recipe.premade(InitUpdateResponse.parse(r.getData(), hc));
                });
    }

    // EXTERNAL AUTHENTICATE (GPC 2.3.1 11.1.4) for DES-based SCPs (SCP01, SCP02)
    public static Recipe<byte[]> ext_authenticate_des(final byte[] hostCryptogram, final int securityLevel,
            final Function<byte[], byte[]> macFn) {
        final var bo = new ByteArrayOutputStream();
        bo.write(CLA_MAC);
        bo.write(INS_EXTERNAL_AUTHENTICATE);
        bo.write(securityLevel);
        bo.write(0x00);
        bo.write(hostCryptogram.length + 8);
        bo.writeBytes(hostCryptogram);

        final var mac = macFn.apply(bo.toByteArray());
        final var data = GPUtils.concatenate(hostCryptogram, mac);

        return send(new CommandAPDU(CLA_MAC, INS_EXTERNAL_AUTHENTICATE, securityLevel, 0x00, data))
                .map(r -> mac);
    }

    // EXTERNAL AUTHENTICATE (GPC 2.3.1 11.1.4) for SCP03 (AES-CMAC, GPC AmdD 6.2.4)
    public static Recipe<byte[]> ext_authenticate_scp03(final byte[] macKey, final byte[] hostCryptogram,
            final int securityLevel, final boolean s16) {
        final byte[] chainingValue = new byte[16];
        final int macLength = s16 ? 16 : 8;
        final var command = new CommandAPDU(CLA_MAC, INS_EXTERNAL_AUTHENTICATE, securityLevel, 0x00, hostCryptogram);

        final var cla = command.getCLA() | 0x04;
        final var lc = command.getNc() + macLength;

        final var bo = new ByteArrayOutputStream();
        bo.writeBytes(chainingValue);
        bo.write(cla);
        bo.write(command.getINS());
        bo.write(command.getP1());
        bo.write(command.getP2());
        bo.writeBytes(GPUtils.encodeLcLength(lc, 0));
        bo.writeBytes(command.getData());

        final byte[] cmac = GPCrypto.aes_cmac(macKey, bo.toByteArray(), 128);
        final byte[] cmdMac = Arrays.copyOf(cmac, macLength);
        final byte[] data = GPUtils.concatenate(command.getData(), cmdMac);

        return send(new CommandAPDU(cla, command.getINS(), command.getP1(), command.getP2(), data))
                .map(r -> cmac);
    }

    // === Per-SCP authentication: verify card crypto + compute host crypto + EXT AUTH -> session state ===

    // SCP01: 3DES cryptograms, context = host||card / card||host
    public static Recipe<SecureChannelState> authenticate_scp01(final InitUpdateResponse response,
            final CardKeys keys, final EnumSet<GPSession.APDUMode> secLevel) {
        final var session = (SessionKeys.SCP01Keys) keys.deriveSession(response.sessionContext());

        final var cardCtx = GPUtils.concatenate(response.hostChallenge(), response.cardChallenge());
        verifyCardCryptogram(response, GPCrypto.mac_3des(cardCtx, session.enc(), new byte[8]));

        final var hostCrypto = GPCrypto.mac_3des(
                GPUtils.concatenate(response.cardChallenge(), response.hostChallenge()),
                session.enc(), new byte[8]);

        return ext_authenticate_des(hostCrypto, GPSession.APDUMode.getSetValue(secLevel),
                macInput -> GPCrypto.mac_3des(macInput, session.mac(), new byte[8]))
                .map(icv -> new SCP01.State(session.enc(), session.mac(), icv, secLevel));
    }

    // SCP02: 3DES cryptograms with sequence counter, context = host||seq||card
    public static Recipe<SecureChannelState> authenticate_scp02(final InitUpdateResponse response,
            final CardKeys keys, final EnumSet<GPSession.APDUMode> secLevel) {
        final var session = (SessionKeys.SCP02Keys) keys.deriveSession(response.sessionContext());

        final var cardCryptoCtx = GPUtils.concatenate(
                response.hostChallenge(), response.sequenceCounter(), response.cardChallenge());
        verifyCardCryptogram(response, GPCrypto.mac_3des(cardCryptoCtx, session.enc(), new byte[8]));

        final var hostCryptoCtx = GPUtils.concatenate(
                response.sequenceCounter(), response.cardChallenge(), response.hostChallenge());
        final var hostCrypto = GPCrypto.mac_3des(hostCryptoCtx, session.enc(), new byte[8]);

        return ext_authenticate_des(hostCrypto, GPSession.APDUMode.getSetValue(secLevel),
                macInput -> GPCrypto.mac_des_3des(session.mac(), macInput, new byte[8]))
                .map(icv -> new SCP02.State(session.enc(), session.mac(), session.rmac(), icv, secLevel));
    }

    // SCP03: AES cryptograms, optional pseudo-random challenge verification
    public static Recipe<SecureChannelState> authenticate_scp03(final InitUpdateResponse response,
            final CardKeys keys, final EnumSet<GPSession.APDUMode> secLevel) {
        final var session = (SessionKeys.SCP03Keys) keys.deriveSession(response.sessionContext());

        // Verify pseudo-random card challenge (if i-parameter bit 4 is set)
        if (response.scpI() != null && (response.scpI() & 0x10) == 0x10 && response.sequenceCounter() != null) {
            final var challengeCtx = GPUtils.concatenate(response.sequenceCounter(), DEFAULT_ISD);
            final var expectedChallenge = keys.kdf(
                    CardKeys.KeyPurpose.ENC,
                    GPCrypto.scp03_kdf_blocka((byte) 0x02, response.s16() ? 128 : 64),
                    challengeCtx,
                    response.s16() ? 16 : 8);
            if (!Arrays.equals(response.cardChallenge(), expectedChallenge)) {
                System.err.println("WARNING: Pseudo-random card challenge does not match expected value");
            }
        }

        final var cardCtx = GPUtils.concatenate(response.hostChallenge(), response.cardChallenge());
        verifyCardCryptogram(response, GPCrypto.scp03_kdf(session.mac(), (byte) 0x00, cardCtx, response.s16() ? 128 : 64));

        final var hostCrypto = GPCrypto.scp03_kdf(session.mac(), (byte) 0x01, cardCtx, response.s16() ? 128 : 64);

        return ext_authenticate_scp03(session.mac(), hostCrypto, GPSession.APDUMode.getSetValue(secLevel), response.s16())
                .map(cv -> new SCP03.State(session.enc(), session.mac(), session.rmac(), cv, secLevel, response.s16()));
    }

    // === Composed: open secure channel ===

    // INIT UPDATE + key derivation + per-SCP authentication -> session state
    // Reads FORCE_S16 preference: if true, uses 16-byte challenge (no fallback).
    // If false (default), init_update uses 8-byte with automatic 6700 retry.
    public static Recipe<SecureChannelState> open_secure_channel(final CardKeys keys,
            final EnumSet<GPSession.APDUMode> securityLevel) {
        final var secLevel = normalize(securityLevel);

        return deferred(prefs -> {
            var hostChallenge = prefs.get(FORCE_S16) ? GPCrypto.random(16) : null;
            return init_update(keys.keyInfo().version(), 0, hostChallenge)
                .then(response -> open_secure_channel_auth(keys, secLevel, response));
        });
    }

    // Explicit host challenge variant (for deterministic testing with MockBIBO)
    public static Recipe<SecureChannelState> open_secure_channel(final CardKeys keys,
            final EnumSet<GPSession.APDUMode> securityLevel, final byte[] hostChallenge) {
        final var secLevel = normalize(securityLevel);

        return init_update(keys.keyInfo().version(), 0, hostChallenge)
                .then(response -> open_secure_channel_auth(keys, secLevel, response));
    }

    // Shared authentication logic after INIT UPDATE
    private static Recipe<SecureChannelState> open_secure_channel_auth(final CardKeys keys,
            final EnumSet<GPSession.APDUMode> secLevel, final InitUpdateResponse response) {
        final var cardKeys = keys.diversify(scp_version(response.scp()), response.diversificationData());
        final var ctx = response.sessionContext();
        return switch (response.scp()) {
            case 0x01 -> authenticate_scp01(response, cardKeys, secLevel)
                    .map(s -> ((SCP01.State) s).withContext(ctx));
            case 0x02 -> authenticate_scp02(response, cardKeys, secLevel)
                    .map(s -> ((SCP02.State) s).withContext(ctx));
            case 0x03 -> authenticate_scp03(response, cardKeys, secLevel)
                    .map(s -> ((SCP03.State) s).withContext(ctx));
            default -> throw new GPException("Unsupported SCP: " + response.scp());
        };
    }

    // === Content management: DELETE (GPC 2.3.1 11.2) ===

    // DELETE an application, package, or security domain by AID
    public static Recipe<ResponseAPDU> delete_aid(final AID aid, final boolean deleteDeps) {
        final var data = TLV.of(Tag.ber(0x4F), aid.getBytes()).encode();
        return gp_dm(INS_DELETE, 0x00, deleteDeps ? 0x80 : 0x00, data, ReceiptVerifier.delete(aid));
    }

    // DELETE key by version and/or ID (GPC 2.3.1 11.2, Table 11-23)
    public static Recipe<ResponseAPDU> delete_key(final Integer keyVersion, final Integer keyId) {
        if (keyVersion == null && keyId == null) {
            throw new IllegalArgumentException("Must specify either key version or key ID");
        }
        final var bo = new ByteArrayOutputStream();
        if (keyId != null) {
            bo.writeBytes(TLV.of(Tag.ber(0xD0), new byte[]{keyId.byteValue()}).encode());
        }
        if (keyVersion != null) {
            bo.writeBytes(TLV.of(Tag.ber(0xD2), new byte[]{keyVersion.byteValue()}).encode());
        }
        return gp(INS_DELETE, 0x00, 0x00, bo.toByteArray());
    }

    // === Content management: LOAD (GPC 2.3.1 11.6) ===

    // INSTALL [for load] (GPC 2.3.1 11.5.2.3.1, Table 11-45)
    public static Recipe<ResponseAPDU> install_for_load(final AID packageAID, final AID targetDomain,
            final byte[] hash, final byte[] loadParams) {
        final var bo = new ByteArrayOutputStream();
        bo.write(packageAID.getLength());
        bo.writeBytes(packageAID.getBytes());
        bo.write(targetDomain.getLength());
        bo.writeBytes(targetDomain.getBytes());
        bo.write(hash.length);
        bo.writeBytes(hash);
        bo.writeBytes(GPUtils.encodeLength(loadParams.length));
        bo.writeBytes(loadParams);
        return gp_dm(INS_INSTALL, 0x02, 0x00, bo.toByteArray(), ReceiptVerifier.load(packageAID, targetDomain));
    }

    // LOAD (GPC 2.3.1 11.6.2.3, Table 11-58) - chunked by BLOCK_SIZE preference
    public static Recipe<ResponseAPDU> load(final byte[] loadBlock) {
        return chunked(INS_LOAD, 0x00, loadBlock);
    }

    // Assemble a load block: optional DAP prefix + C4-tagged code
    public static byte[] build_load_block(final byte[] code, final byte[] dapBlock) {
        final var bo = new ByteArrayOutputStream();
        if (dapBlock != null && dapBlock.length > 0) {
            bo.writeBytes(dapBlock);
        }
        bo.writeBytes(TLV.of(Tag.ber(0xC4), code).encode());
        return bo.toByteArray();
    }

    // Assemble a DAP block (E2 TLV with domain AID + C3 signature)
    public static byte[] build_dap_block(final AID dapDomain, final byte[] dap) {
        return TLV.build(Tag.ber(0xE2))
                .add(Tag.ber(0x4F), dapDomain.getBytes())
                .add(Tag.ber(0xC3), dap)
                .encode();
    }

    // Composed: INSTALL [for load] then LOAD for a CAPFile
    // Reads LOAD_HASH preference for LFDBH algorithm
    // dapBlock: pre-built DAP block (null for none)
    public static Recipe<ResponseAPDU> load_cap(final CAPFile cap, final AID targetDomain, final byte[] dapBlock) {
        return deferred(prefs -> {
            final var hash = cap.getLoadFileDataHash(prefs.get(LOAD_HASH));
            return install_for_load(cap.getPackageAID(), targetDomain, hash, new byte[0])
                    .and(load(build_load_block(cap.getCode(), dapBlock)));
        });
    }

    // Load a CAP file onto the card (no DAP)
    public static Recipe<ResponseAPDU> load_cap_file(final CAPFile cap, final AID targetDomain) {
        return load_cap(cap, targetDomain, null);
    }

    // Load a CAP file onto the card with DAP verification
    public static Recipe<ResponseAPDU> load_cap_file(final CAPFile cap, final AID targetDomain,
            final AID dapDomain, final byte[] dap) {
        return load_cap(cap, targetDomain, build_dap_block(dapDomain, dap));
    }

    // === Content management: INSTALL ===

    // Build INSTALL data payload (shared by install_and_make_selectable and other INSTALL variants)
    // installParams: raw TLV install parameters, or plain app params (auto-wrapped in C9 tag),
    //                or null/empty for default empty C9
    public static byte[] build_install_data(AID packageAID, AID appletAID, AID instanceAID,
            Set<GPRegistryEntryNG.Privilege> privileges, byte[] installParams) {
        if (instanceAID == null) {
            instanceAID = appletAID;
        }
        if (installParams == null || installParams.length == 0) {
            installParams = new byte[]{(byte) 0xC9, 0x00};
        } else {
            // If C9 tag already present, use as-is; otherwise wrap raw bytes in C9
            try {
                if (TLV.find(TLV.parse(installParams), Tag.ber(0xC9)).isPresent()) {
                    // Already valid TLV with C9 - use as-is
                } else {
                    installParams = TLV.of(Tag.ber(0xC9), installParams).encode();
                }
            } catch (TLVParseException e) {
                // Not valid TLV - treat as raw app parameters, wrap in C9
                installParams = TLV.of(Tag.ber(0xC9), installParams).encode();
            }
        }
        final var privs = BitField.encode(privileges, 3);
        final var bo = new ByteArrayOutputStream();
        bo.write(packageAID.getLength());
        bo.writeBytes(packageAID.getBytes());
        bo.write(appletAID.getLength());
        bo.writeBytes(appletAID.getBytes());
        bo.write(instanceAID.getLength());
        bo.writeBytes(instanceAID.getBytes());
        bo.write(privs.length);
        bo.writeBytes(privs);
        bo.writeBytes(GPUtils.encodeLength(installParams.length));
        bo.writeBytes(installParams);
        return bo.toByteArray();
    }

    // INSTALL [for install and make selectable] (GPC 2.3.1 11.5.2.3.2 + 11.5.2.3.3)
    public static Recipe<ResponseAPDU> install_and_make_selectable(AID packageAID, AID appletAID,
            AID instanceAID, Set<GPRegistryEntryNG.Privilege> privileges, byte[] installParams) {
        final var data = build_install_data(packageAID, appletAID, instanceAID, privileges, installParams);
        return gp_dm(INS_INSTALL, 0x0C, 0x00, data, ReceiptVerifier.install_make_selectable(packageAID, instanceAID));
    }

    // === Content management: INSTALL variants (GPC 2.3.1 11.5) ===

    // INSTALL [for extradition] (GPC 2.3.1 11.5.2.3.4, Table 11-47)
    public static Recipe<ResponseAPDU> extradite(final AID what, final AID to) {
        final var bo = new ByteArrayOutputStream();
        bo.write(to.getLength());
        bo.writeBytes(to.getBytes());
        bo.write(0x00);
        bo.write(what.getLength());
        bo.writeBytes(what.getBytes());
        bo.write(0x00);
        bo.write(0x00);
        return deferred(prefs -> {
            var apdu = cmd(INS_INSTALL, 0x10, 0x00, bo.toByteArray());
            var tok = prefs.valueOf(DM_TOKENIZER);
            if (tok.isPresent()) {
                apdu = tok.get().tokenize(apdu);
            }
            var recipe = send(apdu);
            var verifier = prefs.valueOf(RECEIPT_VERIFIER);
            if (verifier.isPresent()) {
                var from = prefs.valueOf(ISD_AID).orElseThrow(() -> new GPException("ISD AID needed for receipt"));
                final var v = verifier.get();
                recipe = recipe.consume(r -> v.check(r, ReceiptVerifier.extradite(from, what, to)));
            }
            return recipe;
        });
    }

    // INSTALL [for make selectable] (GPC 2.3.1 11.5.2.3.3) - set default selected
    public static Recipe<ResponseAPDU> make_default_selected(final AID aid) {
        final var privs = BitField.encode(EnumSet.of(GPRegistryEntryNG.Privilege.CardReset), 3);
        final var bo = new ByteArrayOutputStream();
        bo.write(0x00);
        bo.write(0x00);
        bo.write(aid.getLength());
        bo.writeBytes(aid.getBytes());
        bo.write(privs.length);
        bo.writeBytes(privs);
        bo.write(0x00);
        return gp(INS_INSTALL, 0x08, 0x00, bo.toByteArray());
    }

    // Rename ISD via STORE DATA (GPC 2.3.1 11.11)
    public static Recipe<ResponseAPDU> rename_isd(final AID newAid) {
        final var data = TLV.of(Tag.ber(0x4F), newAid.getBytes()).encode();
        return gp(INS_STORE_DATA, 0x90, 0x00, data);
    }

    // === Card lifecycle: SET STATUS (GPC 2.3.1 11.10) ===

    // SET STATUS for ISD lifecycle
    public static Recipe<ResponseAPDU> set_card_status(final GPRegistryEntryNG.ISDLifeCycle state) {
        return send(cmd(INS_SET_STATUS, 0x80, state.matchValue()));
    }

    // SET STATUS for applet lifecycle
    public static Recipe<ResponseAPDU> set_applet_status(final AID aid, final boolean lock) {
        return gp(INS_SET_STATUS, 0x40, lock ? 0x80 : 0x00, aid.getBytes());
    }

    // === Content management: STORE DATA (GPC 2.3.1 11.11) ===

    // STORE DATA from pre-built CommandAPDUs with P2 renumbering and INS validation
    public static Recipe<ResponseAPDU> store_data(final List<CommandAPDU> commands) {
        final var numbered = new ArrayList<CommandAPDU>(commands.size());
        for (var i = 0; i < commands.size(); i++) {
            final var cmd = commands.get(i);
            if (cmd.getINS() != (INS_STORE_DATA & 0xFF)) {
                throw new IllegalArgumentException("Not a STORE DATA APDU: " + HexUtils.bin2hex(cmd.getBytes()));
            }
            numbered.add(new CommandAPDU(cmd.getCLA(), cmd.getINS(), cmd.getP1(), i, cmd.getData(), 256));
        }
        return send(numbered, 0x9000);
    }

    // STORE DATA from data blocks with P1 and last-block bit management
    public static Recipe<ResponseAPDU> store_data_blocks(final List<byte[]> blocks, final int p1) {
        final var commands = new ArrayList<CommandAPDU>();
        for (var i = 0; i < blocks.size(); i++) {
            final int v = i == blocks.size() - 1 ? p1 | 0x80 : p1 & ~0x80;
            commands.add(cmd(INS_STORE_DATA, v, 0, blocks.get(i)));
        }
        return store_data(commands);
    }

    // STORE DATA blob - chunked by BLOCK_SIZE preference
    public static Recipe<ResponseAPDU> store_data_blob(final byte[] data, final int p1) {
        return chunked(INS_STORE_DATA, p1, data);
    }

    // STORE DATA for DGI blocks with DEK encryption and padding (EMV personalization)
    public static Recipe<ResponseAPDU> store_dgi(List<DGIData> dgiBlocks, CardKeys keys) {
        return deferred(prefs -> {
            var scpVersion = prefs.valueOf(SCP_VERSION);
            var padBlock = scpVersion.map(v -> v.scp == GPSecureChannelVersion.SCP.SCP03 ? 16 : 8).orElse(8);
            var ctx = prefs.valueOf(SESSION_CONTEXT).orElse(new byte[0]);
            var commands = new ArrayList<CommandAPDU>();
            for (var i = 0; i < dgiBlocks.size(); i++) {
                var dgi = dgiBlocks.get(i);
                int p1 = dgi.type() == DGIData.Type.PLAINTEXT ? 0x00 : 0x60;
                var payload = dgi.type() == DGIData.Type.PADDING ? GPCrypto.pad80(dgi.value(), padBlock) : dgi.value();
                if (dgi.type() != DGIData.Type.PLAINTEXT) {
                    payload = keys.encryptDEK(payload, ctx);
                }
                payload = GPUtils.concatenate(dgi.tag(), DGIData.length(payload.length), payload);
                p1 = i == dgiBlocks.size() - 1 ? p1 | 0x80 : p1 & ~0x80;
                commands.add(cmd(INS_STORE_DATA, p1, 0, payload));
            }
            return store_data(commands);
        });
    }

    // INSTALL [for personalization] (GPC 2.3.1 11.5.2.3.6) - associate app with SD
    public static Recipe<ResponseAPDU> install_for_personalization(final AID aid) {
        final var bo = new ByteArrayOutputStream();
        bo.write(0x00);
        bo.write(0x00);
        bo.write(aid.getLength());
        bo.writeBytes(aid.getBytes());
        bo.write(0x00);
        bo.write(0x00);
        bo.write(0x00);
        return gp(INS_INSTALL, 0x20, 0x00, bo.toByteArray());
    }

    // === Key management: PUT KEY (GPC 2.3.1 11.8) ===

    static final int INS_PUT_KEY = 0xD8;

    // PUT KEY with pre-encoded key data (single key, P2=0x01)
    public static Recipe<ResponseAPDU> put_key(final int version, final boolean replace, final byte[] encodedKey) {
        return gp(INS_PUT_KEY, replace ? version : 0x00, 0x01, encodedKey);
    }

    // PUT KEY for a public key (RSA or EC, no wrapping)
    public static Recipe<ResponseAPDU> put_public_key(PublicKey key, int version, boolean replace) {
        var bo = new ByteArrayOutputStream();
        bo.write(version);
        if (key instanceof RSAPublicKey rsaKey) {
            bo.writeBytes(encode_rsa_key(rsaKey));
        } else if (key instanceof ECPublicKey ecKey) {
            bo.writeBytes(encode_ec_key(ecKey));
        } else {
            throw new IllegalArgumentException("Unsupported public key type: " + key.getClass());
        }
        return put_key(version, replace, bo.toByteArray());
    }

    // PUT KEY for a single symmetric key with DEK wrapping (P2=0x01)
    // Deferred: reads SESSION_CONTEXT for wrapping at prepare-time
    public static Recipe<ResponseAPDU> put_symmetric_key(final CardKeys currentKeys, final byte[] rawKey,
            final boolean isAES, final int version, final boolean replace) {
        return deferred(prefs -> {
            var ctx = prefs.valueOf(SESSION_CONTEXT).orElse(new byte[0]);
            var wrapped = currentKeys.wrapKey(rawKey, ctx);
            var kcv = isAES ? GPCrypto.kcv_aes(rawKey) : GPCrypto.kcv_3des(rawKey);
            var bo = new ByteArrayOutputStream();
            bo.write(version);
            if (isAES) {
                bo.write(0x88);
                bo.write(wrapped.length + 1);
                bo.write(rawKey.length);
                bo.writeBytes(wrapped);
            } else {
                bo.write(0x80);
                bo.write(wrapped.length);
                bo.writeBytes(wrapped);
            }
            bo.write(kcv.length);
            bo.writeBytes(kcv);
            return put_key(version, replace, bo.toByteArray());
        });
    }

    // PUT KEY for a full key set (ENC/MAC/DEK) with DEK wrapping (P2=0x81)
    // currentKeys: session keys for DEK wrapping; newKeys: plaintext keys to load
    public static Recipe<ResponseAPDU> put_key_set(final CardKeys currentKeys, final PlaintextCardKeys newKeys,
            final boolean replace) {
        return deferred(prefs -> {
            var ctx = prefs.valueOf(SESSION_CONTEXT).orElse(new byte[0]);
            var bo = new ByteArrayOutputStream();
            bo.write(newKeys.keyInfo().version());
            for (var p : CardKeys.KeyPurpose.cardKeys()) {
                bo.writeBytes(encode_symmetric_key(currentKeys, newKeys, p, ctx));
            }
            return send(cmd(INS_PUT_KEY, replace ? newKeys.keyInfo().version() : 0x00, 0x81, bo.toByteArray()));
        });
    }

    // Diversify keys based on key version range convention (GP 2.3.1)
    static PlaintextCardKeys diversify_by_version(PlaintextCardKeys keys, byte[] kdd, Optional<GPSecureChannelVersion> scpVersion) {
        var keyver = keys.keyInfo().version();
        if (keyver >= 0x10 && keyver <= 0x1F) {
            return (PlaintextCardKeys) keys.diversify(GPSecureChannelVersion.SCP.SCP01, kdd);
        }
        if (keyver >= 0x20 && keyver <= 0x2F) {
            return (PlaintextCardKeys) keys.diversify(GPSecureChannelVersion.SCP.SCP02, kdd);
        }
        if (keyver >= 0x30 && keyver <= 0x3F) {
            return (PlaintextCardKeys) keys.diversify(GPSecureChannelVersion.SCP.SCP03, kdd);
        }
        if (scpVersion.isPresent()) {
            return (PlaintextCardKeys) keys.diversify(scpVersion.get().scp, kdd);
        }
        return keys;
    }

    // PUT KEY for a full key set with auto-diversification based on key version range
    public static Recipe<ResponseAPDU> put_key_set_diversified(CardKeys currentKeys, PlaintextCardKeys newKeys, boolean replace) {
        return deferred(prefs -> {
            var kdd = prefs.valueOf(KDD).orElse(new byte[0]);
            var scpVer = prefs.valueOf(SCP_VERSION);
            var diversified = diversify_by_version(newKeys, kdd, scpVer);
            var ctx = prefs.valueOf(SESSION_CONTEXT).orElse(new byte[0]);
            var bo = new ByteArrayOutputStream();
            bo.write(diversified.keyInfo().version());
            for (var p : CardKeys.KeyPurpose.cardKeys()) {
                bo.writeBytes(encode_symmetric_key(currentKeys, diversified, p, ctx));
            }
            return send(cmd(INS_PUT_KEY, replace ? diversified.keyInfo().version() : 0x00, 0x81, bo.toByteArray()));
        });
    }

    // Encode a symmetric key for PUT KEY: wrap under DEK + KCV
    static byte[] encode_symmetric_key(final CardKeys currentKeys, final PlaintextCardKeys newKeys,
            final CardKeys.KeyPurpose p, final byte[] sessionContext) {
        var raw = newKeys.rawKey(p);
        var wrapped = currentKeys.wrapKey(raw, sessionContext);
        var kcv = newKeys.kcv(p);
        var bo = new ByteArrayOutputStream();
        var info = newKeys.keyInfo();
        if (info.type() == CardKeys.KeyInfo.KeyType.AES) {
            bo.write(0x88); // AES type byte
            bo.write(wrapped.length + 1); // +1 for actual key length prefix
            bo.write(info.length()); // actual key length
            bo.writeBytes(wrapped);
        } else {
            bo.write(0x80); // DES3 type byte
            bo.write(wrapped.length);
            bo.writeBytes(wrapped);
        }
        bo.write(kcv.length);
        bo.writeBytes(kcv);
        return bo.toByteArray();
    }

    // Encode RSA public key for PUT KEY (format 1, no wrapping)
    static byte[] encode_rsa_key(final RSAPublicKey key) {
        var bo = new ByteArrayOutputStream();
        bo.writeBytes(TLV.of(Tag.ber(0xA1), GPUtils.positive(key.getModulus())).encode());
        bo.writeBytes(TLV.of(Tag.ber(0xA0), GPUtils.positive(key.getPublicExponent())).encode());
        bo.write(0x00); // No KCV
        return bo.toByteArray();
    }

    // Encode EC public key for PUT KEY (format 1, no wrapping)
    static byte[] encode_ec_key(final ECPublicKey pubkey) {
        var fieldSize = pubkey.getParams().getCurve().getField().getFieldSize();
        byte curveRef = switch (fieldSize) {
            case 256 -> 0x00;
            case 384 -> 0x01;
            case 521 -> 0x02;
            default -> throw new IllegalArgumentException("Unsupported EC field size: " + fieldSize);
        };
        var curveName = switch (fieldSize) {
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> throw new IllegalArgumentException("Unsupported EC field size: " + fieldSize);
        };
        var point = ECNamedCurveTable.getByName(curveName).getCurve()
                .createPoint(pubkey.getW().getAffineX(), pubkey.getW().getAffineY())
                .getEncoded(false);
        var bo = new ByteArrayOutputStream();
        bo.writeBytes(TLV.of(Tag.ber(0xB0), point).encode());
        bo.writeBytes(TLV.of(Tag.ber(0xF0), new byte[]{curveRef}).encode());
        bo.write(0x00); // No KCV
        return bo.toByteArray();
    }

    // === Personalization: STORE DATA (DGI) ===

    // SET PRE-PERSO data in CPLC (tag 9F67)
    public static Recipe<ResponseAPDU> set_pre_perso(final byte[] data) {
        final var payload = TLV.of(Tag.ber(0x9F67), data).encode();
        return gp(INS_STORE_DATA, 0x80, 0x00, payload);
    }

    // SET PERSO data in CPLC (tag 9F66)
    public static Recipe<ResponseAPDU> set_perso(final byte[] data) {
        final var payload = TLV.of(Tag.ber(0x9F66), data).encode();
        return gp(INS_STORE_DATA, 0x80, 0x00, payload);
    }

    // === Utilities ===

    public static void verifyCardCryptogram(final InitUpdateResponse response, final byte[] expected) {
        if (!Arrays.equals(response.cardCryptogram(), expected)) {
            throw new GPException("Card cryptogram invalid!"
                    + "\nReceived: " + HexUtils.bin2hex(response.cardCryptogram())
                    + "\nExpected: " + HexUtils.bin2hex(expected)
                    + "\n!!! DO NOT RE-TRY THE SAME COMMAND/KEYS OR YOU MAY BRICK YOUR CARD !!!");
        }
    }
}
