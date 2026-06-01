// SPDX-FileCopyrightText: 2012 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2009 Wojciech Mostowski <woj@cs.ru.nl>
// SPDX-FileCopyrightText: 2009 Francois Kooman <F.Kooman@student.science.ru.nl>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.GPKeyInfo.GPKey;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.data.BitField;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVParseException;
import pro.javacard.tlv.TLVs;
import pro.javacard.tlv.Tag;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static pro.javacard.gp.GPCardKeys.KeyPurpose;
import static pro.javacard.gp.GPSecureChannelVersion.SCP.*;
import static pro.javacard.tlv.TLV.ba;

/**
 * Represents a connection to a GlobalPlatform Card (BIBO interface)
 * Does secure channel and low-level translation of GP* objects to APDU-s and arguments
 * NOT thread-safe
 */
public class GPSession {

    public static final int SW_NO_ERROR = 0x9000;
    private static final Logger logger = LoggerFactory.getLogger(GPSession.class);

    public static final EnumSet<APDUMode> defaultMode = EnumSet.of(APDUMode.MAC);
    // Implementation details
    public static final byte CLA_ISO7816 = 0x00;
    public static final byte CLA_GP = (byte) 0x80;
    public static final byte CLA_MAC = (byte) 0x84;

    public static final byte INS_SELECT = (byte) 0xA4;
    public static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
    public static final byte INS_INSTALL = (byte) 0xE6;
    public static final byte INS_LOAD = (byte) 0xE8;
    public static final byte INS_DELETE = (byte) 0xE4;
    public static final byte INS_GET_STATUS = (byte) 0xF2;
    public static final byte INS_SET_STATUS = (byte) 0xF0;
    public static final byte INS_PUT_KEY = (byte) 0xD8;
    public static final byte INS_STORE_DATA = (byte) 0xE2;

    public static final byte INS_EXTERNAL_AUTHENTICATE_82 = (byte) 0x82;
    public static final byte INS_GET_DATA = (byte) 0xCA;

    public static final byte P1_INSTALL_FOR_MAKE_SELECTABLE = (byte) 0x08;
    public static final byte P1_INSTALL_FOR_INSTALL = (byte) 0x04;
    public static final byte P1_INSTALL_AND_MAKE_SELECTABLE = P1_INSTALL_FOR_INSTALL | P1_INSTALL_FOR_MAKE_SELECTABLE;

    public static final byte P1_INSTALL_FOR_LOAD = (byte) 0x02;
    public static final byte P1_MORE_BLOCKS = (byte) 0x00;
    public static final byte P1_LAST_BLOCK = (byte) 0x80;

    public static final int SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
    public static final int SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;

    // (I)SD AID
    private AID sdAID;
    private GPSecureChannelVersion scpVersion;
    private int scpKeyVersion = 0; // will be set to the key version reported by card
    GPCardProfile profile;
    private int blockSize = 255;
    private GPCardKeys cardKeys = null;
    private byte[] sessionContext;
    private SecureChannelWrapper wrapper = null;
    private BIBO channel;
    private GPRegistry registry = null;
    private DMTokenizer tokenizer = DMTokenizer.none();
    private ReceiptVerifier verifier = new ReceiptVerifier.NullVerifier();

    private boolean dirty = true; // True if registry is dirty.

    /*
     * Maintaining locks to the underlying hardware is the duty of the caller
     */
    public GPSession(BIBO channel, AID sdAID) {
        this(channel, sdAID, GPCardProfile.defaultProfile());
    }

    public GPSession(BIBO channel, AID sdAID, GPCardProfile profile) {
        if (channel == null) {
            throw new IllegalArgumentException("A card session is required");
        }
        this.channel = channel;
        this.sdAID = sdAID;
        this.profile = profile;
    }

    // Try to find GlobalPlatform from a card
    public static GPSession discover(final BIBO channel) throws GPException {
        if (channel == null) {
            throw new IllegalArgumentException("channel is null");
        }

        // Try the default
        final var command = new CommandAPDU(CLA_ISO7816, INS_SELECT, 0x04, 0x00, 256);
        final var response = channel.transmit(command);

        // Unfused JCOP replies with 0x6A82 to everything
        if (response.getSW() == 0x6A82) {
            // If it has the identification AID, it probably is an unfused JCOP
            final var identify_aid = HexUtils.hex2bin("A000000167413000FF");
            final var identify = new CommandAPDU(CLA_ISO7816, INS_SELECT, 0x04, 0x00, identify_aid, 256);
            final var identify_resp = channel.transmit(identify);
            final var identify_data = identify_resp.getData();
            // Check the fuse state
            if (identify_data.length > 15) {
                if (identify_data[14] == 0x00) {
                    throw new GPException("Unfused JCOP detected");
                }
            }
        }

        // WORKAROUND: SmartJac UICC
        if (response.getSW() == 0x6A87) {
            // Try the default
            logger.debug("Trying default ISD AID ...");
            return connect(channel, new AID(GPData.defaultISDBytes));
        }

        // 6283 - locked. Pass through locked.
        GPException.check(response, "Could not SELECT default selected", 0x6283);
        if (response.getSW() == 0x6283) {
            logger.warn("Card Manager is LOCKED");
        }

        final TLVs tlvs;
        try {
            // Detect security domain based on default select
            tlvs = TLV.parse(response.getData());
            GPUtils.trace_tlv(response.getData(), logger);
        } catch (TLVParseException e) {
            // WORKAROUND: Exists a card, which returns plain AID as response
            logger.warn("Could not parse SELECT response: " + e.getMessage());
            throw new GPDataException("Could not auto-detect ISD AID", response.getData());
        }

        final var isdaid = tlvs.find(0x6F).flatMap(fci -> fci.find(0x84)).map(TLV::value)
                // WORKAROUND: exists a card that returns a zero length AID in template
                .filter(v -> v.length > 0)
                .orElseThrow(() -> new GPDataException("Could not auto-detect ISD AID", response.getData()));
        final var detectedAID = new AID(isdaid);
        logger.debug("Auto-detected ISD: " + detectedAID);
        return new GPSession(channel, detectedAID);
    }

    // Establishes connection to a specific AID (selects it)
    public static GPSession connect(BIBO channel, AID sdAID) throws GPException {
        if (channel == null) {
            throw new IllegalArgumentException("A card session is required");
        }
        if (sdAID == null) {
            throw new IllegalArgumentException("Security Domain AID is required");
        }

        logger.debug("(I)SD AID: " + sdAID);
        final var gp = new GPSession(channel, sdAID);
        gp.select(sdAID);
        return gp;
    }

    public void setBlockSize(final int size) {
        this.blockSize = size;
    }

    public void setTokenizer(final DMTokenizer tokenizer) {
        this.tokenizer = tokenizer;
    }

    public void setVerifier(final ReceiptVerifier verifier) {
        this.verifier = verifier;
    }

    public DMTokenizer getTokenizer() {
        return tokenizer;
    }

    public AID getAID() {
        return new AID(sdAID.getBytes());
    }

    public GPSecureChannelVersion getSecureChannel() {
        return this.scpVersion;
    }

    public BIBO getCardChannel() {
        return channel;
    }

    /**
     * Return the key version of the keyset used to open this session
     *
     * @return keyset version
     */
    public int getScpKeyVersion() {
        return scpKeyVersion;
    }

    void select(AID sdAID) throws GPException {
        // Try to select ISD (default selected)
        final var command = new CommandAPDU(CLA_ISO7816, INS_SELECT, 0x04, 0x00, sdAID.getBytes(), 256);
        final var resp = channel.transmit(command);

        // If the ISD is locked, log it, but do not stop
        if (resp.getSW() == 0x6283) {
            logger.warn("SELECT returned 6283 - CARD_LOCKED");
        }

        GPException.check(resp, "Could not SELECT", 0x6283);
        parse_select_response(resp.getData());
    }

    private void parse_select_response(final byte[] fci) throws GPException {
        final TLVs tlvs;
        try {
            tlvs = TLV.parse(fci);
            GPUtils.trace_tlv(fci, logger);
        } catch (TLVParseException e) {
            logger.warn("Could not parse SELECT response: " + e.getMessage());
            return;
        }
        tlvs.find(0x6F).ifPresentOrElse(fcitag -> {
            fcitag.find(0x84).ifPresent(isdaid -> {
                final var detectedAID = new AID(isdaid.value());
                if (!detectedAID.equals(sdAID)) {
                    logger.warn("SD AID in FCI (%s) does not match the requested AID (%s). Using reported AID!".formatted(detectedAID, sdAID));
                    // So one can select only the prefix
                    sdAID = detectedAID;
                }
            });

            fcitag.find(0xA5).ifPresentOrElse(prop -> {
                // Tag 73 is a constructed tag.
                prop.find(0x73).ifPresent(isdd -> isdd.find(0x06).ifPresentOrElse(oidtag -> {
                    // 1.2.840.114283.1
                    if (Arrays.equals(oidtag.value(), HexUtils.hex2bin("2A864886FC6B01"))) {
                        // Detect versions
                        isdd.find(0x60).flatMap(vertag -> vertag.find(0x06)).ifPresent(veroid ->
                                // TODO: react to it maybe? Not that relevant in 2.2 era
                                logger.debug("Auto-detected GP version: " + GPData.oid2version(veroid.value())));
                    } else if (GPData.oid2string(oidtag.value()).startsWith("1.2.840.114283.4.") && oidtag.value().length == 9) {
                        final var data = oidtag.value();
                        // SCP version
                        logger.debug("Auto-detected SCP version: {}", GPSecureChannelVersion.valueOf(data[7] & 0xFF, data[8] & 0xFF));
                    } else {
                        logger.warn("Unrecognized card recognition data: {}", HexUtils.bin2hex(oidtag.value()));
                    }
                }, () -> logger.warn("No Global Platform OID found")));

                // Lifecycle
                prop.find(0x9F6E).ifPresent(lc -> logger.debug("Lifecycle data (ignored): " + HexUtils.bin2hex(lc.value())));
                // Max block size
                prop.find(0x9F65).ifPresent(maxbs -> setBlockSize(maxbs.value()));
            }, () -> logger.warn("No mandatory proprietary info present in FCI"));
        }, () -> logger.warn("No FCI returned to SELECT"));
    }

    private void setBlockSize(final byte[] blockSize) {
        final var bs = new BigInteger(1, blockSize).intValue();
        if (bs > this.blockSize) {
            logger.warn("Ignoring auto-detected block size that exceeds set maximum: " + bs);
        } else {
            this.blockSize = bs;
            logger.debug("Auto-detected block size: {}", bs);
        }
    }

    public List<GPKeyInfo> getKeyInfoTemplate() throws GPException {
        final byte[] tmpl;
        if (wrapper != null) {
            tmpl = GPException.check(transmit(new CommandAPDU(CLA_GP, INS_GET_DATA, 0x00, 0xE0, 256)),
                    "GET DATA [Key Information Template] failed").getData();
        } else {
            tmpl = GPData.fetchKeyInfoTemplate(channel);
        }
        return new ArrayList<>(GPKeyInfo.parseTemplate(tmpl));
    }

    private void normalizeSecurityLevel(final EnumSet<APDUMode> securityLevel) {
        // GPC AmdD (SCP03) v1.1.1 7.1.2.1
        if (securityLevel.contains(APDUMode.RENC)) {
            securityLevel.add(APDUMode.ENC);
            securityLevel.add(APDUMode.RMAC);
        }

        if (securityLevel.contains(APDUMode.ENC) || securityLevel.contains(APDUMode.RMAC)) {
            securityLevel.add(APDUMode.MAC);
        }
    }

    /*
     * Establishes a secure channel (INITIALIZE UPDATE + EXTERNAL AUTHENTICATE) to a security domain or application
     */
    @SuppressWarnings("StatementSwitchToExpressionSwitch")
    public void openSecureChannel(GPCardKeys keys, GPSecureChannelVersion scp, byte[] host_challenge, EnumSet<APDUMode> securityLevel)
            throws GPException {

        normalizeSecurityLevel(securityLevel);

        logger.info("Using card master key(s) with version {} for setting up session with {} ", keys.getKeyInfo().getVersion(),
                securityLevel.stream().map(Enum::name).collect(Collectors.joining(", ")));

        // XXX: more explicit SCP indication from tool
        var s16 = (scp != null && scp.scp == SCP03 && (scp.i & 0x01) == 0x01) || (host_challenge != null && host_challenge.length == 16);

        if (s16) {
            logger.debug("Using S16 mode");
        }

        // DWIM: Generate host challenge
        if (host_challenge == null) {
            host_challenge = GPCrypto.random(s16 ? 16 : 8);
            logger.trace("Generated host challenge: " + HexUtils.bin2hex(host_challenge));
        }

        // P1 key version (all)
        // P2 either key ID (SCP01) or 0 (SCP02)
        final int init_p2 = scp != null && scp.scp == GPSecureChannelVersion.SCP.SCP01 ? keys.getKeyInfo().getID() : 0;
        final var initUpdate = new CommandAPDU(CLA_GP, INS_INITIALIZE_UPDATE, keys.getKeyInfo().getVersion(), init_p2, host_challenge, 256);

        var response = channel.transmit(initUpdate);
        final var sw = response.getSW();

        // XXX: Handle 6700 and try again with S16 mode
        if (sw == 0x6700 && !s16) {
            logger.warn("Wrong length with implicit S8 mode. Hoping for S16 mode and trying again.");
            s16 = true;
            host_challenge = GPCrypto.random(s16 ? 16 : 8);
            response = channel.transmit(new CommandAPDU(CLA_GP, INS_INITIALIZE_UPDATE, keys.getKeyInfo().getVersion(), init_p2, host_challenge, 256));
        }

        // Detect and report locked cards in a more sensible way.
        if ((sw == SW_SECURITY_STATUS_NOT_SATISFIED) || (sw == SW_AUTHENTICATION_METHOD_BLOCKED)) {
            throw new GPException(sw, "INITIALIZE UPDATE failed, card LOCKED?");
        }

        // Detect all other errors
        GPException.check(response, "INITIALIZE UPDATE failed");
        final var update_response = response.getData();

        // SCP01:  kdd (10) | key info (2) | card challenge (8) | card cryptogram (8) = 28
        // SCP02:  kdd (10) | key info (2) | seq (2) | card challenge (6) | card cryptogram (8) = 28
        // SCP03 S8:  kdd (10) | key info (3) | card challenge (8) | card cryptogram (8) | seq (3, optional) = 29 (32)
        // SCP03 S16: kdd (10) | key info (3) | card challenge (16) | card cryptogram (16) | seq (3, optional) = 45 (48)
        // key info = kvn | scp | i (scp03) or kvn | scp (scp01/02)

        // Minimal length, as we look into fixed offsets
        if (update_response.length < 28) {
            throw new GPDataException("INITIALIZE UPDATE response with too small length", update_response);
        }

        var update_len = 0;

        switch (update_response[11]) {
            case 0x01:
            case 0x02:
                update_len = 28;
                break;
            case 0x03:
                update_len = 29;
                final var i = update_response[12];
                if ((i & 0x10) == 0x10) {
                    update_len += 3;
                }
                if ((i & 0x01) == 0x01) {
                    if (!s16) {
                        logger.warn("S16 mode reported by card but not requested!");
                    }
                    update_len += 16; // +8 for both challenges
                }
                break;
            default:
                throw new GPDataException("Unsupported SCP version", update_response);
        }

        // Verify response length (SCP01/SCP02 + SCP03 + SCP03 w/ pseudorandom + SCP03 w/ S16)
        if (update_len != update_response.length) {
            throw new GPException("Invalid INITIALIZE UPDATE response length: " + update_response.length);
        }

        // Parse the response
        var offset = 0;
        final byte[] diversification_data = Arrays.copyOfRange(update_response, 0, 10);
        offset += diversification_data.length;

        // Get used key version from response
        scpKeyVersion = update_response[offset] & 0xFF;
        offset++;

        // Get major SCP version from Key Information field in response
        final var scpv = update_response[offset] & 0xFF;
        offset++;

        // get the protocol "i" parameter, if SCP03
        if (scpv == 0x03) {
            this.scpVersion = GPSecureChannelVersion.valueOf(scpv, update_response[offset]);
            offset++;
        } else {
            this.scpVersion = GPSecureChannelVersion.valueOf(scpv);
        }

        // get card challenge
        final byte[] card_challenge = Arrays.copyOfRange(update_response, offset, offset + (s16 ? 16 : 8));
        offset += card_challenge.length;

        // get card cryptogram
        final byte[] card_cryptogram = Arrays.copyOfRange(update_response, offset, offset + (s16 ? 16 : 8));
        offset += card_cryptogram.length;

        // Extract ssc
        final byte[] seq;
        if (this.scpVersion.scp == SCP02) {
            seq = Arrays.copyOfRange(update_response, 12, 14);
        } else if (this.scpVersion.scp == SCP03 && (this.scpVersion.i & 0x10) == 0x10) {
            // XXX instead of throwing if missing, show an error.
            seq = Arrays.copyOfRange(update_response, offset, offset + 3);
        } else {
            seq = null;
        }

        logger.debug("KDD: {}", HexUtils.bin2hex(diversification_data));
        if (seq != null) {
            logger.debug("SSC: {}", HexUtils.bin2hex(seq));
        }
        logger.debug("Host challenge: " + HexUtils.bin2hex(host_challenge));
        logger.debug("Card challenge: " + HexUtils.bin2hex(card_challenge));
        logger.debug("Card reports {} with key version {}", this.scpVersion, GPUtils.intString(scpKeyVersion));

        // Verify response
        // If using explicit key version, it must match.
        final var keyInfo = keys.getKeyInfo();
        if ((keyInfo.getVersion() > 0) && (scpKeyVersion != keyInfo.getVersion())) {
            throw new GPException("Key version mismatch: " + keyInfo.getVersion() + " != " + scpKeyVersion);
        }

        // This will throw as expected later, to indicate the issue
        if (this.scpVersion.scp == GPSecureChannelVersion.SCP.SCP01 && securityLevel.contains(APDUMode.RMAC)) {
            logger.warn("SCP01 does not support RMAC, removing.");
        }

        // Give the card key a chance to be automatically diversified based on KDD from INITIALIZE UPDATE
        cardKeys = keys.diversify(this.scpVersion.scp, diversification_data);

        logger.info("Diversified card keys: {}", cardKeys);

        // Check pseudorandom card challenge. NOTE: this MUST happen _after_ key diversification.
        if (scpVersion.scp == SCP03 && (scpVersion.i & 0x10) == 0x10) {
            final byte[] ctx = GPUtils.concatenate(seq, this.sdAID.getBytes());
            logger.trace("Challenge calculation context: {}", HexUtils.bin2hex(ctx));
            // XXX: remove double length in kdf invocation and harmonize bits vs bytes
            final var my_card_challenge = keys.scp3_kdf(KeyPurpose.ENC, GPCrypto.scp03_kdf_blocka((byte) 0x02, s16 ? 128 : 64), ctx, s16 ? 16 : 8);
            if (!Arrays.equals(my_card_challenge, card_challenge)) {
                logger.warn("Pseudorandom card challenge does not match expected: {} vs {}", HexUtils.bin2hex(my_card_challenge),
                        HexUtils.bin2hex(card_challenge));
            } else {
                logger.debug("Pseudorandom card challenge matches expected value: {}", HexUtils.bin2hex(my_card_challenge));
            }
        }

        // Derive session keys
        if (this.scpVersion.scp == GPSecureChannelVersion.SCP.SCP02) {
            sessionContext = seq.clone();
        } else {
            sessionContext = GPUtils.concatenate(host_challenge, card_challenge);
        }

        final var encKey = cardKeys.getSessionKey(KeyPurpose.ENC, sessionContext);
        final var macKey = cardKeys.getSessionKey(KeyPurpose.MAC, sessionContext);
        final var rmacKey = cardKeys.getSessionKey(KeyPurpose.RMAC, sessionContext);
        logger.info("Session keys: ENC={} MAC={} RMAC={}", HexUtils.bin2hex(encKey), HexUtils.bin2hex(macKey),
                rmacKey == null ? "N/A" : HexUtils.bin2hex(rmacKey));

        // Verify card cryptogram
        byte[] my_card_cryptogram;
        final byte[] cntx = GPUtils.concatenate(host_challenge, card_challenge);
        if (this.scpVersion.scp == SCP01 || this.scpVersion.scp == SCP02) {
            my_card_cryptogram = GPCrypto.mac_3des(cntx, encKey, new byte[8]);
        } else {
            my_card_cryptogram = GPCrypto.scp03_kdf(macKey, (byte) 0x00, cntx, s16 ? 128 : 64);
        }

        // This is the main check for possible successful authentication.
        if (!Arrays.equals(card_cryptogram, my_card_cryptogram)) {
            throw new GPException("Card cryptogram invalid!" +
                    "\nReceived: " + HexUtils.bin2hex(card_cryptogram) +
                    "\nExpected: " + HexUtils.bin2hex(my_card_cryptogram) +
                    "\n!!! DO NOT RE-TRY THE SAME COMMAND/KEYS OR YOU MAY BRICK YOUR CARD !!!");
        } else {
            logger.debug("Verified card cryptogram: " + HexUtils.bin2hex(my_card_cryptogram));
        }

        // Calculate host cryptogram and initialize SCP wrapper
        final byte[] host_cryptogram;
        switch (scpVersion.scp) {
            case SCP01:
                host_cryptogram = GPCrypto.mac_3des(GPUtils.concatenate(card_challenge, host_challenge), encKey, new byte[8]);
                wrapper = new SCP01Wrapper(encKey, macKey, blockSize);
                break;
            case SCP02:
                host_cryptogram = GPCrypto.mac_3des(GPUtils.concatenate(card_challenge, host_challenge), encKey, new byte[8]);
                wrapper = new SCP02Wrapper(encKey, macKey, rmacKey, blockSize);
                break;
            case SCP03:
                host_cryptogram = GPCrypto.scp03_kdf(macKey, (byte) 0x01, cntx, s16 ? 128 : 64);
                wrapper = new SCP03Wrapper(encKey, macKey, rmacKey, blockSize, s16);
                break;
            default:
                throw new IllegalStateException("Unknown SCP");
        }

        logger.debug("Calculated host cryptogram: " + HexUtils.bin2hex(host_cryptogram));
        final var P1 = APDUMode.getSetValue(securityLevel);
        final var externalAuthenticate = new CommandAPDU(CLA_MAC, INS_EXTERNAL_AUTHENTICATE_82, P1, 0, host_cryptogram);
        response = transmit(externalAuthenticate);
        GPException.check(response, "EXTERNAL AUTHENTICATE failed");

        // After opening the session with MAC mode, set it to target level
        wrapper.setSecurityLevel(securityLevel);
    }

    // Pipe through secure channel
    public ResponseAPDU transmit(CommandAPDU command) {
        final var wrapped = wrapper.wrap(command);
        ResponseAPDU resp = null;

        // GPC 2.3.1 11.1.5.1
        final var chunks = GPUtils.splitArray(wrapped.getData(), blockSize);
        if (chunks.size() > 1) {
            logger.debug("Chaining in {} chunks", chunks.size());
        }

        for (var i = 0; i < chunks.size(); i++) {
            final var last = i == chunks.size() - 1;
            final int p1 = last ? command.getP1() : command.getP1() | 0x80; // XXX: should check if instruction is eligible for this treatment
            resp = channel.transmit(new CommandAPDU(wrapped.getCLA(), wrapped.getINS(), p1, wrapped.getP2(), chunks.get(i), 256));
            if (!last) {
                GPException.check(resp);
            }
        }
        return wrapper.unwrap(resp);
    }

    // given a LV APDU content, pretty-print into log
    private ResponseAPDU transmitLV(CommandAPDU command) {
        logger.trace("LV payload: ");
        try {
            GPUtils.trace_lv(command.getData(), logger);
        } catch (Exception e) {
            logger.error("Invalid LV: {}", HexUtils.bin2hex(command.getData()));
        }
        return transmit(command);
    }

    // Given a TLV APDU content, pretty-print into log
    private ResponseAPDU transmitTLV(CommandAPDU command) {
        logger.trace("TLV payload: ");
        try {
            GPUtils.trace_tlv(command.getData(), logger);
        } catch (Exception e) {
            logger.error("Invalid TLV: {}", HexUtils.bin2hex(command.getData()));
        }
        return transmit(command);
    }

    // Simple LOAD without DAP, but possible LFDBH
    public void loadCapFile(CAPFile cap, AID targetDomain, GPData.LFDBH hashFunction) throws GPException {
        if (targetDomain == null) {
            targetDomain = sdAID;
        }
        loadCapFile(cap, targetDomain, null, null, hashFunction);
    }

    public void loadCapFile(CAPFile cap, AID targetDomain, AID dapDomain, byte[] dap, GPData.LFDBH hashFunction)
            throws GPException {
        final byte[] hash = hashFunction == null ? new byte[0] : cap.getLoadFileDataHash(hashFunction.algo);
        final var code = cap.getCode();
        final byte[] loadParams = new byte[0]; // FIXME
        final var pkg = cap.getPackageAID();

        final var bo = new ByteArrayOutputStream();

        bo.write(pkg.getLength());
        bo.writeBytes(pkg.getBytes());

        bo.write(targetDomain.getLength());
        bo.writeBytes(targetDomain.getBytes());

        bo.write(hash.length);
        bo.writeBytes(hash);

        // XXX: would be nice to check in CLI when payload length exceeds encodable length
        bo.writeBytes(GPUtils.encodeLength(loadParams.length));
        bo.writeBytes(loadParams);

        var command = new CommandAPDU(CLA_GP, INS_INSTALL, P1_INSTALL_FOR_LOAD, 0x00, bo.toByteArray(), 256);
        command = tokenizer.tokenize(command);
        var response = transmitLV(command);
        GPException.check(response, "INSTALL [for load] failed");
        verifier.check(response, ReceiptVerifier.load(pkg, targetDomain));

        // Construct load block
        final var loadBlock = new ByteArrayOutputStream();
        // Add DAP block, if signature present. E2 content: [4F AID][C3 DAP]
        if (dap != null && dapDomain != null) {
            loadBlock.writeBytes(TLV.build(0xE2)
                    .add(0x4F, dapDomain.getBytes())
                    .add(0xC3, dap)
                    .encode());
        }
        // See GP 2.1.1 Table 9-40, GP 2.2.1 11.6.2.3 / Table 11-58
        loadBlock.writeBytes(TLV.of(0xC4, code).encode());

        // Split according to available block size
        final var blocks = GPUtils.splitArray(loadBlock.toByteArray(), wrapper.getBlockSize());

        for (var i = 0; i < blocks.size(); i++) {
            final byte p1 = i == (blocks.size() - 1) ? P1_LAST_BLOCK : P1_MORE_BLOCKS;
            final var load = new CommandAPDU(CLA_GP, INS_LOAD, p1, (byte) i, blocks.get(i), 256);
            response = transmit(load);
            GPException.check(response, "LOAD failed");
        }
        // Mark the registry as dirty
        dirty = true;
    }

    public void installAndMakeSelectable(AID packageAID, AID appletAID, AID instanceAID, Set<Privilege> privileges, byte[] installParams)
            throws GPException {
        if (instanceAID == null) {
            instanceAID = appletAID;
        }
        final var data = buildInstallData(packageAID, appletAID, instanceAID, privileges, installParams);
        var command = new CommandAPDU(CLA_GP, INS_INSTALL, P1_INSTALL_AND_MAKE_SELECTABLE, 0x00, data);
        command = tokenizer.tokenize(command);
        final var response = transmitLV(command);
        GPException.check(response, "INSTALL [for install and make selectable] failed");

        verifier.check(response, ReceiptVerifier.install_make_selectable(packageAID, instanceAID));
        dirty = true;
    }

    private byte[] buildInstallData(AID packageAID, AID appletAID, AID instanceAID, Set<Privilege> privileges, byte[] installParams) {
        if (instanceAID == null) {
            instanceAID = appletAID;
        }
        // Empty mandatory app parameters
        if (installParams == null || installParams.length == 0) {
            installParams = TLV.of(0xC9, ba()).encode();
        } else {
            var valid = false;
            // Handle #360 - only modify/fixup installation parameters when needed.
            try {
                final var tlvs = TLV.parse(installParams);
                GPUtils.trace_tlv(installParams, logger);
                // If applications parameters are already present (must not be first tag), do not add anything
                if (tlvs.find(0xC9).isPresent()) {
                    valid = true;
                }
            } catch (TLVParseException e) {
                logger.warn("Installation parameters did not parse as valid TLV, assuming simple app parameters!");
            }
            // Simple use: only unstructured application parameters without existing tag, prepend 0xC9
            if (!valid) {
                installParams = TLV.of(Tag.ber(0xC9), installParams).encode();
            }
        }
        logger.trace("Installation parameters: {}", HexUtils.bin2hex(installParams));

        // Try to use the minimal
        final byte[] privs = BitField.encode(privileges, 3);
        final var bo = new ByteArrayOutputStream();
        bo.write(packageAID.getLength());
        bo.writeBytes(packageAID.getBytes());

        bo.write(appletAID.getLength());
        bo.writeBytes(appletAID.getBytes());

        bo.write(instanceAID.getLength());
        bo.writeBytes(instanceAID.getBytes());

        bo.write(privs.length);
        bo.writeBytes(privs);

        // XXX: See #241. It would be nice to warn if the length exceeds the supported length
        bo.writeBytes(GPUtils.encodeLength(installParams.length));
        bo.writeBytes(installParams);
        return bo.toByteArray();
    }

    public void extradite(final AID what, final AID to) throws GPException {
        // GP 2.2.1 Table 11-45
        final var bo = new ByteArrayOutputStream();
        bo.write(to.getLength());
        bo.writeBytes(to.getBytes());

        bo.write(0x00);
        bo.write(what.getLength());
        bo.writeBytes(what.getBytes());

        bo.write(0x00);

        bo.write(0x00); // no extradition parameters

        var command = new CommandAPDU(CLA_GP, INS_INSTALL, 0x10, 0x00, bo.toByteArray());
        command = tokenizer.tokenize(command);
        final var response = transmitLV(command);
        GPException.check(response, "INSTALL [for extradition] failed");

        verifier.check(response, ReceiptVerifier.extradite(sdAID, what, to));
        dirty = true;
    }

    public void installForPersonalization(final AID aid) throws GPException {
        // send the INSTALL for personalization command
        final var bo = new ByteArrayOutputStream();
        // GP 2.1.1 9.5.2.3.5, 2.2.1 - 11.5.2.3.6
        bo.write(0);
        bo.write(0);
        bo.write(aid.getLength());
        bo.writeBytes(aid.getBytes());
        bo.write(0);
        bo.write(0);
        bo.write(0);
        final var install = new CommandAPDU(CLA_GP, INS_INSTALL, 0x20, 0x00, bo.toByteArray(), 256);
        GPException.check(transmitLV(install), "INSTALL [for personalization] failed");
    }

    // Core: caller provides CommandAPDUs with P1 fully set (including b8 last-block).
    // Method only replaces P2 with sequential counter, then wraps through secure channel.
    public List<byte[]> storeData(final List<CommandAPDU> commands) throws GPException {
        if (commands.size() > 256) {
            throw new IllegalArgumentException("Too many STORE DATA blocks: " + commands.size() + " (max 256)");
        }
        final var results = new ArrayList<byte[]>();
        for (var i = 0; i < commands.size(); i++) {
            final var cmd = commands.get(i);
            if (cmd.getINS() != (INS_STORE_DATA & 0xFF)) {
                throw new IllegalArgumentException("Not a STORE DATA command: INS=" + "%02X".formatted(cmd.getINS()));
            }
            final var numbered = new CommandAPDU(cmd.getCLA(), cmd.getINS(), cmd.getP1(), i, cmd.getData(), 256);
            results.add(GPException.check(transmit(numbered), "STORE DATA failed").getData());
        }
        return results;
    }

    // All blocks share one P1; auto-sets b8 on last block
    public List<byte[]> storeData(final List<byte[]> blocks, final int p1) throws GPException {
        return storeData(buildStoreDataCommands(blocks, p1));
    }

    // Build STORE DATA CommandAPDUs with correct P1 last-block bit management
    public static List<CommandAPDU> buildStoreDataCommands(final List<byte[]> blocks, final int p1) {
        final var commands = new ArrayList<CommandAPDU>();
        for (var i = 0; i < blocks.size(); i++) {
            final int v = i == blocks.size() - 1 ? p1 | P1_LAST_BLOCK : p1 & ~P1_LAST_BLOCK;
            commands.add(new CommandAPDU(CLA_GP, INS_STORE_DATA, v, 0, blocks.get(i)));
        }
        return commands;
    }

    // Auto-splits large blob by wrapper block size, uniform P1
    public List<byte[]> storeData(byte[] data, int p1) throws GPException {
        return storeData(GPUtils.splitArray(data, wrapper.getBlockSize()), p1);
    }

    public void makeDefaultSelected(final AID aid) throws GPException {
        final var bo = new ByteArrayOutputStream();
        // Only supported privilege.
        final byte[] privileges = BitField.encode(EnumSet.of(Privilege.CardReset), 3);

        bo.write(0);
        bo.write(0);
        bo.write(aid.getLength());
        bo.writeBytes(aid.getBytes());
        bo.write(privileges.length);
        bo.writeBytes(privileges);
        bo.write(0);

        var command = new CommandAPDU(CLA_GP, INS_INSTALL, P1_INSTALL_FOR_MAKE_SELECTABLE, 0x00, bo.toByteArray());
        command = tokenizer.tokenize(command);
        final var response = transmitLV(command);
        GPException.check(response, "INSTALL [for make selectable] failed");
        dirty = true;
    }

    public void lockUnlockApplet(final AID app, final boolean lock) throws GPException {
        final var cmd = new CommandAPDU(CLA_GP, INS_SET_STATUS, 0x40, lock ? 0x80 : 0x00, app.getBytes());
        final var response = transmit(cmd);
        GPException.check(response, "SET STATUS failed");
        dirty = true;
    }

    public void setCardStatus(final GPRegistryEntry.ISDLifeCycle status) throws GPException {
        logger.debug("Setting status to {}", status);
        final var cmd = new CommandAPDU(CLA_GP, INS_SET_STATUS, 0x80, status.getValue());
        final var response = transmit(cmd);
        GPException.check(response, "SET STATUS failed");
        dirty = true;
    }

    // Delete file aid on the card. Delete dependencies as well if deleteDeps is true.
    public void deleteAID(final AID aid, final boolean deleteDeps) throws GPException {
        final var data = TLV.of(0x4F, aid.getBytes()).encode();
        var command = new CommandAPDU(CLA_GP, INS_DELETE, 0x00, deleteDeps ? 0x80 : 0x00, data);
        command = tokenizer.tokenize(command);
        final var response = transmitTLV(command);
        GPException.check(response, "DELETE failed");
        verifier.check(response, ReceiptVerifier.delete(aid));
        dirty = true;
    }

    public void deleteKey(final Integer keyver, final Integer keyid) throws GPException {
        // TODO: get id from existing template list

        if (keyid == null && keyver == null) {
            throw new IllegalArgumentException("Must specify either key version or key ID");
        }

        final var fields = new ArrayList<TLV>();
        if (keyid != null) {
            fields.add(TLV.of(0xD0, ba(keyid))); // Key Identifier
        }
        if (keyver != null) {
            fields.add(TLV.of(0xD2, ba(keyver))); // Key Version Number
        }

        final var delete = new CommandAPDU(CLA_GP, INS_DELETE, 0x00, 0x00, TLV.encode(fields));
        final var response = transmit(delete);
        // XXX: better message
        final var msg = "DELETE failed for key %s".formatted(keyver != null ? GPUtils.intString(keyver) : GPUtils.intString(keyid));
        GPException.check(response, msg);
    }

    public void renameISD(final AID newaid) throws GPException {
        final var rename = new CommandAPDU(CLA_GP, INS_STORE_DATA, 0x90, 0x00,
                TLV.of(0x4F, newaid.getBytes()).encode());
        final var response = transmit(rename);
        GPException.check(response, "Rename failed");
    }

    public byte[] encryptDEK(final byte[] plaintext) throws GeneralSecurityException {
        return cardKeys.encrypt(plaintext, sessionContext);
    }

    public static byte[] encodeKey(final GPCardKeys dek, final byte[] other, final GPKeyInfo.GPKey type, final byte[] sessionContext) {
        try {
            final var baos = new ByteArrayOutputStream();
            if (type == GPKey.AES) {
                // Pad with random
                final var n = other.length % 16 + 1;
                final byte[] plaintext = GPCrypto.random(n * other.length);
                System.arraycopy(other, 0, plaintext, 0, other.length);

                final var cgram = dek.encrypt(plaintext, sessionContext);
                final byte[] kcv = GPCrypto.kcv_aes(other);
                baos.write(GPKey.AES.getType());
                baos.write(cgram.length + 1); // +1 for actual length
                baos.write(other.length);
                baos.writeBytes(cgram);
                baos.write(kcv.length);
                baos.writeBytes(kcv);
            } else if (type == GPKey.DES3) {
                final var cgram = dek.encrypt(other, sessionContext);
                final byte[] kcv = GPCrypto.kcv_3des(other);
                baos.write(GPKey.DES3.getType());
                baos.write(cgram.length); // Length
                baos.writeBytes(cgram);
                baos.write(kcv.length);
                baos.writeBytes(kcv);
            }
            return baos.toByteArray();
        } catch (GeneralSecurityException e) {
            throw new GPException("Could not wrap key", e);
        }
    }

    private byte[] encodeKey(final GPCardKeys dek, final GPCardKeys other, final KeyPurpose p) {
        try {
            final var baos = new ByteArrayOutputStream();
            if (other.getKeyInfo().getType() == GPKey.AES) {
                final var cgram = dek.encryptKey(other, p, sessionContext);
                final var kcv = other.kcv(p);

                baos.write(GPKey.AES.getType());
                baos.write(cgram.length + 1); // +1 for actual length
                baos.write(other.getKeyInfo().getLength()); // Actual key length
                baos.writeBytes(cgram);
                baos.write(kcv.length);
                baos.writeBytes(kcv);
            } else if (other.getKeyInfo().getType() == GPKey.DES3) {
                final var cgram = dek.encryptKey(other, p, sessionContext);
                final var kcv = other.kcv(p);

                baos.write(GPKey.DES3.getType());
                baos.write(cgram.length); // Length
                baos.writeBytes(cgram);
                baos.write(kcv.length);
                baos.writeBytes(kcv);
            }
            return baos.toByteArray();
        } catch (GeneralSecurityException e) {
            throw new GPException("Could not wrap key", e);
        }
    }

    public void putKeys(final GPCardKeys keys, final boolean replace) throws GPException {

        // Log and trace
        logger.debug("PUT KEY version {} replace={} {}", keys.getKeyInfo().getVersion(), replace, keys);

        // Construct APDU
        var P1 = 0x00; // New key in single command unless replace
        if (replace) {
            P1 = keys.getKeyInfo().getVersion();
        }
        // int P2 = keys.get(0).getID();
        var P2 = 0x01;
        P2 |= 0x80; // More than one key

        final var bo = new ByteArrayOutputStream();
        // New key version
        bo.write(keys.getKeyInfo().getVersion());
        // Key data
        for (KeyPurpose p : KeyPurpose.cardKeys()) {
            bo.writeBytes(encodeKey(cardKeys, keys, p));
        }

        final var command = new CommandAPDU(CLA_GP, INS_PUT_KEY, P1, P2, bo.toByteArray());
        final var response = transmit(command);
        GPException.check(response, "PUT KEY failed");
        // TODO: compare and complain
        if (response.getData().length > 1) {
            final var resp = response.getData();
            final var kv = resp[0] & 0xFF;
            final byte[] kcvs = Arrays.copyOfRange(resp, 1, resp.length);
            final var kcvstrings = GPUtils.splitArray(kcvs, 3).stream().map(HexUtils::bin2hex).collect(Collectors.toList());
            logger.info("Card stored keys with KVN {} and with KCV-s: {}", GPUtils.intString(kv), String.join(", ", kcvstrings));
        }
    }

    public static void encodeRSAKey(final ByteArrayOutputStream bo, final RSAPublicKey key) {
        // A1 modulus, A0 exponent, trailing 0x00 = no KCV
        bo.writeBytes(TLV.of(0xA1, GPUtils.positive(key.getModulus())).encode());
        bo.writeBytes(TLV.of(0xA0, GPUtils.positive(key.getPublicExponent())).encode());
        bo.write(0x00);
    }

    public static void encodeECKey(final ByteArrayOutputStream bo, final ECPublicKey pubkey) {
        final var fieldSize = pubkey.getParams().getCurve().getField().getFieldSize();
        final var curveName = switch (fieldSize) {
            case 256 -> "secp256r1";
            case 384 -> "secp384r1";
            case 521 -> "secp521r1";
            default -> throw new IllegalArgumentException("Unsupported EC field size: " + fieldSize);
        };
        final byte curveRef = switch (fieldSize) {
            case 256 -> 0x00;
            case 384 -> 0x01;
            case 521 -> 0x02;
            default -> throw new IllegalArgumentException("Unsupported EC field size: " + fieldSize);
        };
        final var key = ECNamedCurveTable.getByName(curveName).getCurve().createPoint(pubkey.getW().getAffineX(), pubkey.getW().getAffineY())
                .getEncoded(false);

        // B0 EC public key, F0 curve reference, trailing 0x00 = no KCV
        bo.writeBytes(TLV.of(0xB0, key).encode());
        bo.writeBytes(TLV.of(0xF0, ba(curveRef)).encode());
        bo.write(0x00);
    }

    // Puts a public or otherwise plaintext key (for DAP/DM purposes (format 1))
    public void putKey(final Key key, final int version, final boolean replace) throws GPException {
        final var bo = new ByteArrayOutputStream();
        bo.write(version); // Key Version number

        if (key instanceof RSAPublicKey rsaKey) {
            encodeRSAKey(bo, rsaKey);
        } else if (key instanceof ECPublicKey ecKey) {
            encodeECKey(bo, ecKey);
        } else if (key instanceof SecretKey sk) {
            if ("DESede".equals(sk.getAlgorithm())) {
                logger.info("PUT KEY KCV: {}", HexUtils.bin2hex(GPCrypto.kcv_3des(sk.getEncoded())));
                bo.writeBytes(encodeKey(cardKeys, Arrays.copyOf(sk.getEncoded(), 16), GPKey.DES3, sessionContext));
            } else if ("AES".equals(sk.getAlgorithm())) {
                logger.info("PUT KEY KCV: {}", HexUtils.bin2hex(GPCrypto.kcv_aes(sk.getEncoded())));
                bo.writeBytes(encodeKey(cardKeys, sk.getEncoded(), GPKey.AES, sessionContext));
            } else {
                throw new IllegalArgumentException("Only 3DES and AES symmetric keys are supported: " + sk.getAlgorithm());
            }
        }

        final var command = new CommandAPDU(CLA_GP, INS_PUT_KEY, replace ? version : 0x00, 0x01, bo.toByteArray(), 256);
        final var response = transmit(command);
        GPException.check(response, "PUT KEY failed");
        if (response.getData().length > 1) {
            final var resp = response.getData();
            final var kv = resp[0] & 0xFF;
            final byte[] kcvs = Arrays.copyOfRange(resp, 1, resp.length);
            final var kcvstrings = GPUtils.splitArray(kcvs, 3).stream().map(HexUtils::bin2hex).collect(Collectors.toList());
            logger.info("Card stored key(s) {} with KCV(s) {}", GPUtils.intString(kv), String.join(", ", kcvstrings));
        }
    }

    public void setProfile(final GPCardProfile profile) {
        this.profile = profile;
    }

    public GPCardProfile getProfile() {
        return profile;
    }

    public GPRegistry getRegistry() throws GPException {
        if (dirty) {
            registry = getStatus();
            dirty = false;
        }
        return registry;
    }

    public GPRegistryEntry getCurrentDomain() {
        return getRegistry().getDomain(getAID()).orElseThrow(() -> new IllegalStateException("Current domain not in registry?"));
    }

    public boolean delegatedManagementEnabled() {
        return !(tokenizer instanceof DMTokenizer.NULLTokenizer);
    }

    private byte[] getConcatenatedStatus(int p1, byte[] data, boolean useTags) throws GPException {
        // By default use tags
        final int p2 = useTags ? 0x02 : 0x00;

        var cmd = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, p2, data, 256);
        var response = transmit(cmd);

        // Workaround for legacy cards, like SCE 6.0 FIXME: this does not work properly
        // Find a different way to adjust the response parser without touching the overall spec mode
        // If ISD-s are asked and none is returned, it could be either
        // - SSD
        // - no support for tags
        if (p1 == 0x80 && response.getSW() == 0x6A86) {
            if (p2 == 0x02) {
                // If no support for tags. Re-issue command without requesting tags
                return getConcatenatedStatus(p1, data, false);
            }
        }

        final var sw = response.getSW();
        if ((sw != SW_NO_ERROR) && (sw != 0x6310)) {
            // Possible values:
            if (sw == 0x6A88) {
                // No data to report
                return response.getData();
            }
            // Filter out common noise when modules are not reported by card.
            // 6A86 (Incorrect P1/P2) and 6A81 (Function not supported) for P1=0x10 mean
            // the card does not support Executable Module listing.
            // Neither is a defined GET STATUS error - GPC 2.3.1 Table 11-39
            if ((sw == 0x6A86 || sw == 0x6A81) && p1 == 0x10) {
                logger.debug("GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()) + " with " + GPData.sw2str(response.getSW()));
            } else {
                logger.warn("GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()) + " with " + GPData.sw2str(response.getSW()));
            }
            return response.getData();
        }

        final var bo = new ByteArrayOutputStream();
        bo.writeBytes(response.getData());
        while (response.getSW() == 0x6310 && response.getData().length > 0) {
            cmd = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, p2 | 0x01, data, 256);
            response = transmit(cmd);
            GPException.check(response, "GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()), 0x6310);
            bo.writeBytes(response.getData());
        }
        return bo.toByteArray();
    }

    private GPRegistry getStatus() throws GPException {
        final var registry = new GPRegistry();

        // Issuer security domain
        var data = getConcatenatedStatus(0x80, ba(0x4F, 0x00), profile.getStatusUsesTags());
        registry.parse_and_populate(0x80, data, Kind.ISD, profile);

        // Apps and security domains
        data = getConcatenatedStatus(0x40, ba(0x4F, 0x00), profile.getStatusUsesTags());
        registry.parse_and_populate(0x40, data, Kind.APP, profile);

        // Load files with modules is better than just load files. Registry does not allow to update
        // existing entries
        if (profile.doesReportModules()) {
            // Load files with modules
            data = getConcatenatedStatus(0x10, ba(0x4F, 0x00), profile.getStatusUsesTags());
            registry.parse_and_populate(0x10, data, Kind.PKG, profile);
        }

        // Load files
        data = getConcatenatedStatus(0x20, ba(0x4F, 0x00), profile.getStatusUsesTags());
        registry.parse_and_populate(0x20, data, Kind.PKG, profile);

        return registry;
    }

    public enum APDUMode {
        // bit values as expected by EXTERNAL AUTHENTICATE
        CLR(0x00), MAC(0x01), ENC(0x02), RMAC(0x10), RENC(0x20);

        private final int value;

        APDUMode(final int value) {
            this.value = value;
        }

        public static int getSetValue(final EnumSet<APDUMode> s) {
            var v = 0;
            for (APDUMode m : s) {
                v |= m.value;
            }
            return v;
        }

        public static APDUMode fromString(final String s) {
            return valueOf(s.trim().toUpperCase(Locale.ROOT));
        }
    }
}
