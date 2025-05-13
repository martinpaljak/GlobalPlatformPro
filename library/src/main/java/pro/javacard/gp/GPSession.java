/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 * Copyright (C) 2014-present Martin Paljak, martin@martinpaljak.net
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
 *
 */

package pro.javacard.gp;

import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import com.payneteasy.tlv.*;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.GPKeyInfo.GPKey;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static pro.javacard.gp.GPCardKeys.KeyPurpose;
import static pro.javacard.gp.GPSecureChannelVersion.SCP.*;

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

    public static final byte P1_INSTALL_AND_MAKE_SELECTABLE = (byte) 0x0C;
    public static final byte P1_INSTALL_FOR_INSTALL = (byte) 0x04;
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
    private APDUBIBO channel;
    private GPRegistry registry = null;
    private DMTokenizer tokenizer = DMTokenizer.none();
    private ReceiptVerifier verifier = new ReceiptVerifier.NullVerifier();

    private boolean dirty = true; // True if registry is dirty.

    /*
     * Maintaining locks to the underlying hardware is the duty of the caller
     */
    public GPSession(APDUBIBO channel, AID sdAID) {
        this(channel, sdAID, GPCardProfile.defaultProfile());
    }

    public GPSession(APDUBIBO channel, AID sdAID, GPCardProfile profile) {
        if (channel == null) {
            throw new IllegalArgumentException("A card session is required");
        }
        this.channel = channel;
        this.sdAID = sdAID;
        this.profile = profile;
    }

    // Try to find GlobalPlatform from a card
    public static GPSession discover(APDUBIBO channel) throws GPException, IOException {
        if (channel == null)
            throw new IllegalArgumentException("channel is null");

        // Try the default
        final CommandAPDU command = new CommandAPDU(CLA_ISO7816, INS_SELECT, 0x04, 0x00, 256);
        ResponseAPDU response = channel.transmit(command);

        // Unfused JCOP replies with 0x6A82 to everything
        if (response.getSW() == 0x6A82) {
            // If it has the identification AID, it probably is an unfused JCOP
            byte[] identify_aid = HexUtils.hex2bin("A000000167413000FF");
            CommandAPDU identify = new CommandAPDU(CLA_ISO7816, INS_SELECT, 0x04, 0x00, identify_aid, 256);
            ResponseAPDU identify_resp = channel.transmit(identify);
            byte[] identify_data = identify_resp.getData();
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
        if (response.getSW() == 0x6283)
            logger.warn("Card Manager is LOCKED");

        final BerTlvs tlvs;
        try {
            // Detect security domain based on default select
            BerTlvParser parser = new BerTlvParser();
            tlvs = parser.parse(response.getData());
            GPUtils.trace_tlv(response.getData(), logger);
        } catch (ArrayIndexOutOfBoundsException | IllegalStateException e) {
            // WORKAROUND: Exists a card, which returns plain AID as response
            logger.warn("Could not parse SELECT response: " + e.getMessage());
            throw new GPDataException("Could not auto-detect ISD AID", response.getData());
        }

        BerTlv fcitag = tlvs.find(new BerTag(0x6F));
        if (fcitag != null) {
            BerTlv isdaid = fcitag.find(new BerTag(0x84));
            // WORKAROUND: exists a card that returns a zero length AID in template
            if (isdaid != null && isdaid.getBytesValue().length > 0) {
                AID detectedAID = new AID(isdaid.getBytesValue());
                logger.debug("Auto-detected ISD: " + detectedAID);
                return new GPSession(channel, detectedAID);
            }
        }
        throw new GPDataException("Could not auto-detect ISD AID", response.getData());
    }

    // Establishes connection to a specific AID (selects it)
    public static GPSession connect(APDUBIBO channel, AID sdAID) throws IOException, GPException {
        if (channel == null) {
            throw new IllegalArgumentException("A card session is required");
        }
        if (sdAID == null) {
            throw new IllegalArgumentException("Security Domain AID is required");
        }

        logger.debug("(I)SD AID: " + sdAID);
        GPSession gp = new GPSession(channel, sdAID);
        gp.select(sdAID);
        return gp;
    }

    /*
     * Get the version and build information of the library.
     */
    public static String getVersion() {
        Properties prop = new Properties();
        try (InputStream versionfile = GPSession.class.getResourceAsStream("git.properties")) {
            // if built from targzip and/or with -Dmaven.gitcommitid.skip=true
            if (versionfile == null) {
                return "unsupported";
            }
            prop.load(versionfile);
            return prop.getProperty("git.commit.id.describe", "unknown-development");
        } catch (IOException e) {
            return "unknown-error";
        }
    }

    public void setBlockSize(int size) {
        this.blockSize = size;
    }

    public void setTokenizer(DMTokenizer tokenizer) {
        this.tokenizer = tokenizer;
    }

    public void setVerifier(ReceiptVerifier verifier) {
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

    public APDUBIBO getCardChannel() {
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
        final CommandAPDU command = new CommandAPDU(CLA_ISO7816, INS_SELECT, 0x04, 0x00, sdAID.getBytes(), 256);
        ResponseAPDU resp = channel.transmit(command);

        // If the ISD is locked, log it, but do not stop
        if (resp.getSW() == 0x6283) {
            logger.warn("SELECT returned 6283 - CARD_LOCKED");
        }

        GPException.check(resp, "Could not SELECT", 0x6283);
        parse_select_response(resp.getData());
    }

    private void parse_select_response(byte[] fci) throws GPException {
        final BerTlvs tlvs;
        try {
            BerTlvParser parser = new BerTlvParser();
            tlvs = parser.parse(fci);
            GPUtils.trace_tlv(fci, logger);
        } catch (ArrayIndexOutOfBoundsException | IllegalStateException e) {
            logger.warn("Could not parse SELECT response: " + e.getMessage());
            return;
        }
        BerTlv fcitag = tlvs.find(new BerTag(0x6F));
        if (fcitag != null) {
            BerTlv isdaid = fcitag.find(new BerTag(0x84));
            if (isdaid != null) {
                AID detectedAID = new AID(isdaid.getBytesValue());
                if (!detectedAID.equals(sdAID)) {
                    logger.warn(String.format("SD AID in FCI (%s) does not match the requested AID (%s). Using reported AID!", detectedAID, sdAID));
                    // So one can select only the prefix
                    sdAID = detectedAID;
                }
            }

            //
            BerTlv prop = fcitag.find(new BerTag(0xA5));
            if (prop != null) {

                BerTlv isdd = prop.find(new BerTag(0x73));
                if (isdd != null) {
                    // Tag 73 is a constructed tag.
                    BerTlv oidtag = isdd.find(new BerTag(0x06));
                    if (oidtag != null) {
                        // 1.2.840.114283.1
                        if (Arrays.equals(oidtag.getBytesValue(), HexUtils.hex2bin("2A864886FC6B01"))) {
                            // Detect versions
                            BerTlv vertag = isdd.find(new BerTag(0x60));
                            if (vertag != null) {
                                BerTlv veroid = vertag.find(new BerTag(0x06));
                                if (veroid != null) {
                                    // TODO: react to it maybe? Not that relevant in 2.2 era
                                    logger.debug("Auto-detected GP version: " + GPData.oid2version(veroid.getBytesValue()));
                                }
                            }
                        } else if (GPData.oid2string(oidtag.getBytesValue()).startsWith("1.2.840.114283.4.") && oidtag.getBytesValue().length == 9) {
                            byte[] data = oidtag.getBytesValue();
                            // SCP version
                            logger.debug("Auto-detected SCP version: {}", GPSecureChannelVersion.valueOf(data[7] & 0xFF, data[8] & 0xFF));
                        } else {
                            logger.warn("Unrecognized card recognition data: {}", HexUtils.bin2hex(oidtag.getBytesValue()));
                        }
                    } else {
                        logger.warn("No Global Platform OID found");
                    }
                }

                // Lifecycle
                BerTlv lc = prop.find(new BerTag(0x9F, 0x6E));
                if (lc != null) {
                    logger.debug("Lifecycle data (ignored): " + HexUtils.bin2hex(lc.getBytesValue()));
                }
                // Max block size
                BerTlv maxbs = prop.find(new BerTag(0x9F, 0x65));
                if (maxbs != null) {
                    setBlockSize(maxbs.getBytesValue());
                }
            } else {
                logger.warn("No mandatory proprietary info present in FCI");
            }
        } else {
            logger.warn("No FCI returned to SELECT");
        }
    }

    private void setBlockSize(byte[] blocksize) {
        int bs = new BigInteger(1, blocksize).intValue();
        if (bs > this.blockSize) {
            logger.warn("Ignoring auto-detected block size that exceeds set maximum: " + bs);
        } else {
            this.blockSize = bs;
            logger.debug("Auto-detected block size: " + blockSize);
        }
    }

    public List<GPKeyInfo> getKeyInfoTemplate() throws IOException, GPException {
        final byte[] tmpl;
        if (wrapper != null) {
            // FIXME: check for 0x9000
            tmpl = transmit(new CommandAPDU(CLA_GP, INS_GET_DATA, 0x00, 0xE0, 256)).getData();
        } else {
            tmpl = GPData.fetchKeyInfoTemplate(channel);
        }
        return new ArrayList<>(GPKeyInfo.parseTemplate(tmpl));
    }

    private void normalizeSecurityLevel(EnumSet<APDUMode> securityLevel) {
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
    public void openSecureChannel(GPCardKeys keys, GPSecureChannelVersion scp, byte[] host_challenge, EnumSet<APDUMode> securityLevel)
            throws IOException, GPException {

        normalizeSecurityLevel(securityLevel);

        logger.info("Using card master key(s) with version {} for setting up session with {} ", keys.getKeyInfo().getVersion(), securityLevel.stream().map(Enum::name).collect(Collectors.joining(", ")));

        // XXX: more explicit SCP indication from tool
        boolean s16 = (scp != null && scp.scp == SCP03 && (scp.i & 0x01) == 0x01) || (host_challenge != null && host_challenge.length == 16);

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
        int init_p2 = (scp != null && scp.scp == GPSecureChannelVersion.SCP.SCP01) ? keys.getKeyInfo().getID() : 0;
        CommandAPDU initUpdate = new CommandAPDU(CLA_GP, INS_INITIALIZE_UPDATE, keys.getKeyInfo().getVersion(), init_p2, host_challenge, 256);

        ResponseAPDU response = channel.transmit(initUpdate);
        int sw = response.getSW();

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
        byte[] update_response = response.getData();

        // SCP01:  kdd (10) | key info (2) | card challenge (8) | card cryptogram (8) = 28
        // SCP02:  kdd (10) | key info (2) | seq (2) | card challenge (6) | card cryptogram (8) = 28
        // SCP03 S8:  kdd (10) | key info (3) | card challenge (8) | card cryptogram (8) | seq (3, optional) = 29 (32)
        // SCP03 S16: kdd (10) | key info (3) | card challenge (16) | card cryptogram (16) | seq (3, optional) = 45 (48)
        // key info = kvn | scp | i (scp03) or kvn | scp (scp01/02)

        // Minimal length, as we look into fixed offsets
        if (update_response.length < 28) {
            throw new GPDataException("INITIALIZE UPDATE response with too small length", update_response);
        }

        int update_len = 0;

        switch (update_response[11]) {
            case 0x01:
            case 0x02:
                update_len = 28;
                break;
            case 0x03:
                update_len = 29;
                int i = update_response[12];
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
        int offset = 0;
        byte[] diversification_data = Arrays.copyOfRange(update_response, 0, 10);
        offset += diversification_data.length;

        // Get used key version from response
        scpKeyVersion = update_response[offset] & 0xFF;
        offset++;

        // Get major SCP version from Key Information field in response
        int scpv = update_response[offset] & 0xFF;
        offset++;

        // get the protocol "i" parameter, if SCP03
        if (scpv == 0x03) {
            this.scpVersion = GPSecureChannelVersion.valueOf(scpv, update_response[offset]);
            offset++;
        } else {
            this.scpVersion = GPSecureChannelVersion.valueOf(scpv);
        }

        // get card challenge
        byte[] card_challenge = Arrays.copyOfRange(update_response, offset, offset + (s16 ? 16 : 8));
        offset += card_challenge.length;

        // get card cryptogram
        byte[] card_cryptogram = Arrays.copyOfRange(update_response, offset, offset + (s16 ? 16 : 8));
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
        if (seq != null)
            logger.debug("SSC: {}", HexUtils.bin2hex(seq));
        logger.debug("Host challenge: " + HexUtils.bin2hex(host_challenge));
        logger.debug("Card challenge: " + HexUtils.bin2hex(card_challenge));
        logger.debug("Card reports {} with key version {}", this.scpVersion, GPUtils.intString(scpKeyVersion));

        // Verify response
        // If using explicit key version, it must match.
        GPKeyInfo keyInfo = keys.getKeyInfo();
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
            byte[] ctx = GPUtils.concatenate(seq, this.sdAID.getBytes());
            logger.trace("Challenge calculation context: {}", HexUtils.bin2hex(ctx));
            // XXX: remove double length in kdf invocation and harmonize bits vs bytes
            byte[] my_card_challenge = keys.scp3_kdf(KeyPurpose.ENC, GPCrypto.scp03_kdf_blocka((byte) 0x02, s16 ? 128 : 64), ctx, s16 ? 16 : 8);
            if (!Arrays.equals(my_card_challenge, card_challenge)) {
                logger.warn("Pseudorandom card challenge does not match expected: {} vs {}", HexUtils.bin2hex(my_card_challenge), HexUtils.bin2hex(card_challenge));
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

        byte[] encKey = cardKeys.getSessionKey(KeyPurpose.ENC, sessionContext);
        byte[] macKey = cardKeys.getSessionKey(KeyPurpose.MAC, sessionContext);
        byte[] rmacKey = cardKeys.getSessionKey(KeyPurpose.RMAC, sessionContext);
        logger.info("Session keys: ENC={} MAC={} RMAC={}", HexUtils.bin2hex(encKey), HexUtils.bin2hex(macKey), rmacKey == null ? "N/A" : HexUtils.bin2hex(rmacKey));

        // Verify card cryptogram
        byte[] my_card_cryptogram;
        byte[] cntx = GPUtils.concatenate(host_challenge, card_challenge);
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
        int P1 = APDUMode.getSetValue(securityLevel);
        CommandAPDU externalAuthenticate = new CommandAPDU(CLA_MAC, INS_EXTERNAL_AUTHENTICATE_82, P1, 0, host_cryptogram);
        response = transmit(externalAuthenticate);
        GPException.check(response, "EXTERNAL AUTHENTICATE failed");

        // After opening the session with MAC mode, set it to target level
        wrapper.setSecurityLevel(securityLevel);
    }

    // Pipe through secure channel
    public ResponseAPDU transmit(CommandAPDU command) throws IOException {
        try {
            CommandAPDU wrapped = wrapper.wrap(command);
            ResponseAPDU resp = null;

            // GPC 2.3.1 11.1.5.1
            List<byte[]> chunks = GPUtils.splitArray(wrapped.getData(), blockSize);
            if (chunks.size() > 1)
                logger.debug("Chaining in {} chunks", chunks.size());

            for (int i = 0; i < chunks.size(); i++) {
                boolean last = i == chunks.size() - 1;
                int p1 = last ? command.getP1() : command.getP1() | 0x80; // XXX: should check if instruction is eligible for this treatment
                resp = channel.transmit(new CommandAPDU(wrapped.getCLA(), wrapped.getINS(), p1, wrapped.getP2(), chunks.get(i), 256));
                if (!last) {
                    GPException.check(resp);
                }
            }
            return wrapper.unwrap(resp);
        } catch (GPException e) {
            throw new IOException("Secure channel failure: " + e.getMessage(), e);
        }
    }

    // given a LV APDU content, pretty-print into log
    private ResponseAPDU transmitLV(CommandAPDU command) throws IOException {
        logger.trace("LV payload: ");
        try {
            GPUtils.trace_lv(command.getData(), logger);
        } catch (Exception e) {
            logger.error("Invalid LV: {}", HexUtils.bin2hex(command.getData()));
        }
        return transmit(command);
    }

    // Given a TLV APDU content, pretty-print into log
    private ResponseAPDU transmitTLV(CommandAPDU command) throws IOException {
        logger.trace("TLV payload: ");
        try {
            GPUtils.trace_tlv(command.getData(), logger);
        } catch (Exception e) {
            logger.error("Invalid TLV: {}", HexUtils.bin2hex(command.getData()));
        }
        return transmit(command);
    }

    // Simple LOAD without DAP, but possible LFDBH
    public void loadCapFile(CAPFile cap, AID targetDomain, GPData.LFDBH hashFunction) throws IOException, GPException {
        if (targetDomain == null)
            targetDomain = sdAID;
        loadCapFile(cap, targetDomain, null, null, hashFunction);
    }

    public void loadCapFile(CAPFile cap, AID targetDomain, AID dapDomain, byte[] dap, GPData.LFDBH hashFunction)
            throws GPException, IOException {
        byte[] hash = hashFunction == null ? new byte[0] : cap.getLoadFileDataHash(hashFunction.algo);
        byte[] code = cap.getCode();
        byte[] loadParams = new byte[0]; // FIXME
        AID pkg = cap.getPackageAID();

        ByteArrayOutputStream bo = new ByteArrayOutputStream();

        try {
            bo.write(pkg.getLength());
            bo.write(pkg.getBytes());

            bo.write(targetDomain.getLength());
            bo.write(targetDomain.getBytes());

            bo.write(hash.length);
            bo.write(hash);

            // XXX: would be nice to check in CLI when payload length exceeds encodable length
            bo.write(GPUtils.encodeLength(loadParams.length));
            bo.write(loadParams);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        CommandAPDU command = new CommandAPDU(CLA_GP, INS_INSTALL, P1_INSTALL_FOR_LOAD, 0x00, bo.toByteArray(), 256);
        command = tokenizer.tokenize(command);
        ResponseAPDU response = transmitLV(command);
        GPException.check(response, "INSTALL [for load] failed");
        verifier.check(response, ReceiptVerifier.load(pkg, targetDomain));

        // Construct load block
        ByteArrayOutputStream loadBlock = new ByteArrayOutputStream();
        try {
            // Add DAP block, if signature present
            if (dap != null && dapDomain != null) {
                loadBlock.write(0xE2);
                loadBlock.write(GPUtils.encodeLength(dapDomain.getLength() + dap.length + GPUtils.encodeLength(dap.length).length + 3)); // two tags, two lengths FIXME: proper size
                loadBlock.write(0x4F);
                loadBlock.write(dapDomain.getLength());
                loadBlock.write(dapDomain.getBytes());
                loadBlock.write(0xC3);
                loadBlock.write(GPUtils.encodeLength(dap.length));
                loadBlock.write(dap);
            }
            // See GP 2.1.1 Table 9-40, GP 2.2.1 11.6.2.3 / Table 11-58
            loadBlock.write(0xC4);
            loadBlock.write(GPUtils.encodeLength(code.length));
            loadBlock.write(code);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Split according to available block size
        List<byte[]> blocks = GPUtils.splitArray(loadBlock.toByteArray(), wrapper.getBlockSize());

        for (int i = 0; i < blocks.size(); i++) {
            byte p1 = (i == (blocks.size() - 1)) ? P1_LAST_BLOCK : P1_MORE_BLOCKS;
            CommandAPDU load = new CommandAPDU(CLA_GP, INS_LOAD, p1, (byte) i, blocks.get(i), 256);
            response = transmit(load);
            GPException.check(response, "LOAD failed");
        }
        // Mark the registry as dirty
        dirty = true;
    }

    public void installAndMakeSelectable(AID packageAID, AID appletAID, AID instanceAID, Set<Privilege> privileges, byte[] installParams) throws GPException, IOException {
        if (instanceAID == null) {
            instanceAID = appletAID;
        }
        byte[] data = buildInstallData(packageAID, appletAID, instanceAID, privileges, installParams);
        CommandAPDU command = new CommandAPDU(CLA_GP, INS_INSTALL, P1_INSTALL_AND_MAKE_SELECTABLE, 0x00, data);
        command = tokenizer.tokenize(command);
        ResponseAPDU response = transmitLV(command);
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
            installParams = new byte[]{(byte) 0xC9, 0x00};
        } else {
            boolean valid = false;
            // Handle #360 - only modify/fixup installation parameters when needed.
            try {
                BerTlvParser parser = new BerTlvParser();
                final BerTlvs tlvs = parser.parse(installParams);
                GPUtils.trace_tlv(installParams, logger);
                // If applications parameters are already present (must not be first tag), do not add anything
                if (tlvs.find(new BerTag(0xC9)) != null) {
                    valid = true;
                }
            } catch (ArrayIndexOutOfBoundsException | IllegalStateException e) {
                logger.warn("Installation parameters did not parse as valid TLV, assuming simple app parameters!");
            }
            // Simple use: only unstructured application parameters without existing tag, prepend 0xC9
            if (!valid) {
                installParams = new BerTlvBuilder().addBytes(new BerTag(0xC9), installParams).buildArray();
            }
        }
        logger.trace("Installation parameters: {}", HexUtils.bin2hex(installParams));

        // Try to use the minimal
        byte[] privs = Privilege.toByteOrBytes(privileges);
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            bo.write(packageAID.getLength());
            bo.write(packageAID.getBytes());

            bo.write(appletAID.getLength());
            bo.write(appletAID.getBytes());

            bo.write(instanceAID.getLength());
            bo.write(instanceAID.getBytes());

            bo.write(privs.length);
            bo.write(privs);

            // XXX: See #241. It would be nice to warn if the length exceeds the supported length
            bo.write(GPUtils.encodeLength(installParams.length));
            bo.write(installParams);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return bo.toByteArray();
    }

    public void extradite(AID what, AID to) throws GPException, IOException {
        // GP 2.2.1 Table 11-45
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            bo.write(to.getLength());
            bo.write(to.getBytes());

            bo.write(0x00);
            bo.write(what.getLength());
            bo.write(what.getBytes());

            bo.write(0x00);

            bo.write(0x00); // no extradition parameters
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        CommandAPDU command = new CommandAPDU(CLA_GP, INS_INSTALL, 0x10, 0x00, bo.toByteArray());
        command = tokenizer.tokenize(command);
        ResponseAPDU response = transmitLV(command);
        GPException.check(response, "INSTALL [for extradition] failed");

        verifier.check(response, ReceiptVerifier.extradite(sdAID, what, to));
        dirty = true;
    }


    public void installForPersonalization(AID aid) throws IOException, GPException {
        // send the INSTALL for personalization command
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            // GP 2.1.1 9.5.2.3.5, 2.2.1 - 11.5.2.3.6
            bo.write(0);
            bo.write(0);
            bo.write(aid.getLength());
            bo.write(aid.getBytes());
            bo.write(0);
            bo.write(0);
            bo.write(0);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        CommandAPDU install = new CommandAPDU(CLA_GP, INS_INSTALL, 0x20, 0x00, bo.toByteArray(), 256);
        GPException.check(transmitLV(install), "INSTALL [for personalization] failed");
    }

    public byte[] personalizeSingle(AID aid, byte[] data, int P1) throws IOException, GPException {
        return personalize(aid, Collections.singletonList(data), P1).get(0);
    }

    /*
     * Sends STORE DATA commands to the application identified via SD
     */
    public void personalize(AID aid, byte[] data, int P1) throws IOException, GPException {
        installForPersonalization(aid);
        // Now pump the data
        storeData(data, P1);
    }


    public List<byte[]> personalize(AID aid, List<byte[]> data, int P1) throws IOException, GPException {
        installForPersonalization(aid);
        return storeData(data, P1);
    }


    public byte[] storeDataSingle(byte[] data, int P1) throws IOException, GPException {
        if (data.length > wrapper.getBlockSize()) {
            throw new IllegalArgumentException("block size is bigger than possibility to send: " + data.length + ">" + wrapper.getBlockSize());
        }
        return storeData(Collections.singletonList(data), P1).get(0);
    }

    // Send a GP-formatted STORE DATA block, splitting it into pieces if/as necessary
    public void storeData(byte[] data, int P1) throws IOException, GPException {
        List<byte[]> blocks = GPUtils.splitArray(data, wrapper.getBlockSize());
        storeData(blocks, P1);
    }

    // Send a GP-formatted STORE DATA blocks
    public List<byte[]> storeData(List<byte[]> blocks, int P1) throws IOException, GPException {
        List<byte[]> result = new ArrayList<>();
        for (int i = 0; i < blocks.size(); i++) {
            int p1 = (i == (blocks.size() - 1)) ? P1 | 0x80 : P1 & 0x7F;
            CommandAPDU store = new CommandAPDU(CLA_GP, INS_STORE_DATA, p1, i, blocks.get(i), 256);
            result.add(GPException.check(transmit(store), "STORE DATA failed").getData());
        }
        return result;
    }

    public byte[] storeDataSingle(byte[] data, int P1, int P2) throws IOException, GPException {
        CommandAPDU store = new CommandAPDU(CLA_GP, INS_STORE_DATA, P1, P2, data, 256);
        return GPException.check(transmit(store), "STORE DATA failed").getData();
    }

    public void makeDefaultSelected(AID aid) throws IOException, GPException {
        // FIXME: only works for some 2.1.1 cards ? Clarify and document
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        // Only supported privilege.
        byte privileges = Privilege.toByte(EnumSet.of(Privilege.CardReset));

        try {
            bo.write(0);
            bo.write(0);
            bo.write(aid.getLength());
            bo.write(aid.getBytes());
            bo.write(1);
            bo.write(privileges);
            bo.write(0);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        CommandAPDU command = new CommandAPDU(CLA_GP, INS_INSTALL, 0x08, 0x00, bo.toByteArray());
        command = tokenizer.tokenize(command);
        ResponseAPDU response = transmitLV(command);
        GPException.check(response, "INSTALL [for make selectable] failed");
        dirty = true;
    }

    public void lockUnlockApplet(AID app, boolean lock) throws IOException, GPException {
        CommandAPDU cmd = new CommandAPDU(CLA_GP, INS_SET_STATUS, 0x40, lock ? 0x80 : 0x00, app.getBytes());
        ResponseAPDU response = transmit(cmd);
        GPException.check(response, "SET STATUS failed");
        dirty = true;
    }

    public void setCardStatus(byte status) throws IOException, GPException {
        logger.debug("Setting status to {}", GPRegistryEntry.getLifeCycleString(Kind.IssuerSecurityDomain, status));
        CommandAPDU cmd = new CommandAPDU(CLA_GP, INS_SET_STATUS, 0x80, status);
        ResponseAPDU response = transmit(cmd);
        GPException.check(response, "SET STATUS failed");
        dirty = true;
    }

    /*
     * Delete file {@code aid} on the card. Delete dependencies as well if
     * {@code deleteDeps} is true.
     */
    public void deleteAID(AID aid, boolean deleteDeps) throws GPException, IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            bo.write(0x4f);
            bo.write(aid.getLength());
            bo.write(aid.getBytes());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        CommandAPDU command = new CommandAPDU(CLA_GP, INS_DELETE, 0x00, deleteDeps ? 0x80 : 0x00, bo.toByteArray());
        command = tokenizer.tokenize(command);
        ResponseAPDU response = transmitTLV(command);
        GPException.check(response, "DELETE failed");
        verifier.check(response, ReceiptVerifier.delete(aid));
        dirty = true;
    }

    public void deleteKey(Integer keyver, Integer keyid) throws GPException, IOException {
        // TODO: get id from existing template list

        if (keyid == null && keyver == null)
            throw new IllegalArgumentException("Must specify either key version or key ID");

        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        if (keyid != null) {
            bo.write(0xd0); // Key Identifier
            bo.write(1);
            bo.write(0x01);
        }

        if (keyver != null) {
            bo.write(0xd2); // Key Version Number
            bo.write(1); // length
            bo.write(keyver);
        }

        CommandAPDU delete = new CommandAPDU(CLA_GP, INS_DELETE, 0x00, 0x00, bo.toByteArray());
        ResponseAPDU response = transmit(delete);
        // XXX: better message
        String msg = String.format("DELETE failed for key %s", keyver != null ? GPUtils.intString(keyver) : GPUtils.intString(keyid));
        GPException.check(response, msg);
    }

    public void renameISD(AID newaid) throws GPException, IOException {
        CommandAPDU rename = new CommandAPDU(CLA_GP, INS_STORE_DATA, 0x90, 0x00, GPUtils.concatenate(new byte[]{0x4f, (byte) newaid.getLength()}, newaid.getBytes()));
        ResponseAPDU response = transmit(rename);
        GPException.check(response, "Rename failed");
    }

    public byte[] encryptDEK(byte[] plaintext) throws GeneralSecurityException {
        return cardKeys.encrypt(plaintext, sessionContext);
    }

    private byte[] encodeKey(GPCardKeys dek, byte[] other, GPKeyInfo.GPKey type) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            if (type == GPKey.AES) {
                // Pad with random
                int n = other.length % 16 + 1;
                byte[] plaintext = GPCrypto.random(n * other.length);
                System.arraycopy(other, 0, plaintext, 0, other.length);

                byte[] cgram = dek.encrypt(plaintext, sessionContext);
                byte[] kcv = GPCrypto.kcv_aes(other);
                baos.write(GPKey.AES.getType());
                baos.write(cgram.length + 1); // +1 for actual length
                baos.write(other.length);
                baos.write(cgram);
                baos.write(kcv.length);
                baos.write(kcv);
            } else if (type == GPKey.DES3) {
                byte[] cgram = dek.encrypt(other, sessionContext);
                byte[] kcv = GPCrypto.kcv_3des(other);
                baos.write(GPKey.DES3.getType());
                baos.write(cgram.length); // Length
                baos.write(cgram);
                baos.write(kcv.length);
                baos.write(kcv);
            }
            return baos.toByteArray();
        } catch (IOException | GeneralSecurityException e) {
            throw new GPException("Could not wrap key", e);
        }
    }

    private byte[] encodeKey(GPCardKeys dek, GPCardKeys other, KeyPurpose p) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            if (other.getKeyInfo().getType() == GPKey.AES) {
                byte[] cgram = dek.encryptKey(other, p, sessionContext);
                byte[] kcv = other.kcv(p);

                baos.write(GPKey.AES.getType());
                baos.write(cgram.length + 1); // +1 for actual length
                baos.write(other.getKeyInfo().getLength()); // Actual key length
                baos.write(cgram);
                baos.write(kcv.length);
                baos.write(kcv);
            } else if (other.getKeyInfo().getType() == GPKey.DES3) {
                byte[] cgram = dek.encryptKey(other, p, sessionContext);
                byte[] kcv = other.kcv(p);

                baos.write(GPKey.DES3.getType());
                baos.write(cgram.length); // Length
                baos.write(cgram);
                baos.write(kcv.length);
                baos.write(kcv);
            }
            return baos.toByteArray();
        } catch (IOException | GeneralSecurityException e) {
            throw new GPException("Could not wrap key", e);
        }
    }

    public void putKeys(GPCardKeys keys, boolean replace) throws GPException, IOException {

        // Log and trace
        logger.debug("PUT KEY version {} replace={} {}", keys.getKeyInfo().getVersion(), replace, keys);

        // Construct APDU
        int P1 = 0x00; // New key in single command unless replace
        if (replace) {
            P1 = keys.getKeyInfo().getVersion();
        }
        // int P2 = keys.get(0).getID();
        int P2 = 0x01;
        P2 |= 0x80; // More than one key

        ByteArrayOutputStream bo = new ByteArrayOutputStream();

        // New key version
        bo.write(keys.getKeyInfo().getVersion());
        // Key data
        for (KeyPurpose p : KeyPurpose.cardKeys()) {
            bo.write(encodeKey(cardKeys, keys, p));
        }

        CommandAPDU command = new CommandAPDU(CLA_GP, INS_PUT_KEY, P1, P2, bo.toByteArray());
        ResponseAPDU response = transmit(command);
        GPException.check(response, "PUT KEY failed");
        // TODO: compare and complain
        if (response.getData().length > 1) {
            byte [] resp = response.getData();
            int kv = resp[0] & 0xFF;
            byte[] kcvs = Arrays.copyOfRange(resp, 1, resp.length);
            List<String> kcvstrings = GPUtils.splitArray(kcvs, 3).stream().map(HexUtils::bin2hex).collect(Collectors.toList());
            logger.info("Card stored keys with KVN {} and with KCV-s: {}", GPUtils.intString(kv), String.join(", ", kcvstrings));
        }
    }


    byte[] encodeRSAKey(RSAPublicKey key) {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            byte[] modulus = GPUtils.positive(key.getModulus());
            byte[] exponent = GPUtils.positive(key.getPublicExponent());

            bo.write(0xA1); // Modulus
            bo.write(GPUtils.encodeLength(modulus.length));
            bo.write(modulus);
            bo.write(0xA0);
            bo.write(GPUtils.encodeLength(exponent.length));
            bo.write(exponent);
            bo.write(0x00); // No KCV
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return bo.toByteArray();
    }

    // FIXME: other curves
    byte[] encodeECKey(ECPublicKey pubkey) {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();

        try {
            byte[] key = ECNamedCurveTable.getByName("secp256r1").getCurve().createPoint(pubkey.getW().getAffineX(), pubkey.getW().getAffineY()).getEncoded(false);

            bo.write(0xB0); // EC Public key
            bo.write(key.length);
            bo.write(key);
            bo.write(0xF0); // ECC key parameters reference
            bo.write(0x01);
            bo.write(0x00); // P-256
            bo.write(0x00); // No KCV
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return bo.toByteArray();
    }

    // Puts a public or otherwise plaintext key (for DAP/DM purposes (format 1))
    public void putKey(Key key, int version, boolean replace) throws IOException, GPException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();

        bo.write(version); // Key Version number

        if (key instanceof RSAPublicKey) {
            bo.write(encodeRSAKey((RSAPublicKey) key));
        } else if (key instanceof ECPublicKey) {
            bo.write(encodeECKey((ECPublicKey) key));
        } else if (key instanceof SecretKey) {
            SecretKey sk = (SecretKey) key;
            if (sk.getAlgorithm().equals("DESede")) {
                logger.info("PUT KEY KCV: {}", HexUtils.bin2hex(GPCrypto.kcv_3des(sk.getEncoded())));
                bo.write(encodeKey(cardKeys, Arrays.copyOf(sk.getEncoded(), 16), GPKey.DES3));
            }
            if (sk.getAlgorithm().equals("AES")) {
                logger.info("PUT KEY KCV: {}", HexUtils.bin2hex(GPCrypto.kcv_aes(sk.getEncoded())));
                bo.write(encodeKey(cardKeys, sk.getEncoded(), GPKey.AES));
            } else
                throw new IllegalArgumentException("Only 3DES and AES symmetric keys are supported: " + sk.getAlgorithm());
        }

        CommandAPDU command = new CommandAPDU(CLA_GP, INS_PUT_KEY, replace ? version : 0x00, 0x01, bo.toByteArray(), 256);
        ResponseAPDU response = transmit(command);
        GPException.check(response, "PUT KEY failed");
        if (response.getData().length > 1) {
            byte [] resp = response.getData();
            int kv = resp[0] & 0xFF;
            byte[] kcvs = Arrays.copyOfRange(resp, 1, resp.length);
            List<String> kcvstrings = GPUtils.splitArray(kcvs, 3).stream().map(HexUtils::bin2hex).collect(Collectors.toList());
            logger.info("Card stored key(s) {} with KCV(s) {}", GPUtils.intString(kv), String.join(", ", kcvstrings));
        }
    }


    public void setProfile(GPCardProfile profile) {
        this.profile = profile;
    }

    public GPCardProfile getProfile() {
        return profile;
    }

    public GPRegistry getRegistry() throws GPException, IOException {
        if (dirty) {
            registry = getStatus();
            dirty = false;
        }
        return registry;
    }

    public GPRegistryEntry getCurrentDomain() throws IOException {
        return getRegistry().getDomain(getAID()).orElseThrow(() -> new IllegalStateException("Current domain not in registry?"));
    }

    public boolean delegatedManagementEnabled() {
        return !(tokenizer instanceof DMTokenizer.NULLTokenizer);
    }

    private byte[] getConcatenatedStatus(int p1, byte[] data, boolean useTags) throws IOException, GPException {
        // By default use tags
        int p2 = useTags ? 0x02 : 0x00;

        CommandAPDU cmd = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, p2, data, 256);
        ResponseAPDU response = transmit(cmd);

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

        int sw = response.getSW();
        if ((sw != SW_NO_ERROR) && (sw != 0x6310)) {
            // Possible values:
            if (sw == 0x6A88) {
                // No data to report
                return response.getData();
            }
            // Filter out common noise when modules are not reported by card.
            if (sw == 0x6A86 && p1 == 0x10) {
                logger.debug("GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()) + " with " + GPData.sw2str(response.getSW()));
            } else {
                // 0x6A86 - no tags support or ISD asked from SSD
                // 0a6A81 - Same as 6A88 ?
                logger.warn("GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()) + " with " + GPData.sw2str(response.getSW()));
            }
            return response.getData();
        }

        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            bo.write(response.getData());
            while (response.getSW() == 0x6310 && response.getData().length > 0) {
                cmd = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, p2 | 0x01, data, 256);
                response = transmit(cmd);
                GPException.check(response, "GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()), 0x6310);
                bo.write(response.getData());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return bo.toByteArray();
    }

    private GPRegistry getStatus() throws IOException, GPException {
        GPRegistry registry = new GPRegistry();

        // Issuer security domain
        byte[] data = getConcatenatedStatus(0x80, new byte[]{0x4F, 0x00}, profile.getStatusUsesTags());
        registry.parse_and_populate(0x80, data, Kind.IssuerSecurityDomain, profile);

        // Apps and security domains
        data = getConcatenatedStatus(0x40, new byte[]{0x4F, 0x00}, profile.getStatusUsesTags());
        registry.parse_and_populate(0x40, data, Kind.Application, profile);

        // Load files with modules is better than just load files. Registry does not allow to update
        // existing entries
        if (profile.doesReportModules()) {
            // Load files with modules
            data = getConcatenatedStatus(0x10, new byte[]{0x4F, 0x00}, profile.getStatusUsesTags());
            registry.parse_and_populate(0x10, data, Kind.ExecutableLoadFile, profile);
        }

        // Load files
        data = getConcatenatedStatus(0x20, new byte[]{0x4F, 0x00}, profile.getStatusUsesTags());
        registry.parse_and_populate(0x20, data, Kind.ExecutableLoadFile, profile);

        return registry;
    }


    public enum APDUMode {
        // bit values as expected by EXTERNAL AUTHENTICATE
        CLR(0x00), MAC(0x01), ENC(0x02), RMAC(0x10), RENC(0x20);

        private final int value;

        APDUMode(int value) {
            this.value = value;
        }

        public static int getSetValue(EnumSet<APDUMode> s) {
            int v = 0;
            for (APDUMode m : s) {
                v |= m.value;
            }
            return v;
        }

        public static APDUMode fromString(String s) {
            return valueOf(s.trim().toUpperCase());
        }
    }
}
