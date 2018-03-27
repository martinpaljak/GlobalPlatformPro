/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 * Copyright (C) 2014-2017 Martin Paljak, martin@martinpaljak.net
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

import apdu4j.HexUtils;
import apdu4j.ISO7816;
import com.payneteasy.tlv.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.GPKey.Type;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPRegistryEntry.Privileges;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import static pro.javacard.gp.PlaintextKeys.diversify;

/**
 * Represents a connection to a GlobalPlatform Card (BIBO interface)
 * Does secure channel and low-level translation of GP* objects to APDU-s and arguments
 * NOT thread-safe
 */
public class GlobalPlatform implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(GlobalPlatform.class);

    public static final int SCP_ANY = 0;
    public static final int SCP_01_05 = 1;
    public static final int SCP_01_15 = 2;
    public static final int SCP_02_04 = 3;
    public static final int SCP_02_05 = 4;
    public static final int SCP_02_0A = 5;
    public static final int SCP_02_0B = 6;
    public static final int SCP_02_14 = 7;
    public static final int SCP_02_15 = 8;
    public static final int SCP_02_1A = 9;
    public static final int SCP_02_1B = 10;
    public static final EnumSet<APDUMode> defaultMode = EnumSet.of(APDUMode.MAC);
    // Implementation details
    public static final byte CLA_GP = (byte) 0x80;
    public static final byte CLA_MAC = (byte) 0x84;

    public static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
    public static final byte INS_INSTALL = (byte) 0xE6;
    public static final byte INS_LOAD = (byte) 0xE8;
    public static final byte INS_DELETE = (byte) 0xE4;
    public static final byte INS_GET_STATUS = (byte) 0xF2;
    public static final byte INS_SET_STATUS = (byte) 0xF0;
    public static final byte INS_PUT_KEY = (byte) 0xD8;
    public static final byte INS_STORE_DATA = (byte) 0xE2;
    public static final byte INS_GET_DATA = (byte) 0xCA;
    protected boolean strict = true;
    GPSpec spec = GPSpec.GP211;

    // (I)SD AID successfully selected or null
    private AID sdAID = null;
    // Either 1 or 2 or 3
    private int scpMajorVersion = 0;
    private int scpKeyVersion = 0;

    private int blockSize = 255;
    private GPSessionKeyProvider sessionKeys = null;
    private SCPWrapper wrapper = null;
    private CardChannel channel;
    private GPRegistry registry = null;
    private boolean dirty = true; // True if registry is dirty.
    private byte[] kdd = null;
    /**
     * Maintaining locks to the underlying hardware is the duty of the caller
     *
     * @param channel channel to talk to
     * @throws IllegalArgumentException if {@code channel} is null.
     */
    public GlobalPlatform(CardChannel channel, AID sdAID) {
        if (channel == null) {
            throw new IllegalArgumentException("A card session is required");
        }
        this.channel = channel;
        this.sdAID = sdAID;
    }

    // Try to find GlobalPlatform from a card
    public static GlobalPlatform discover(CardChannel channel) throws GPException, CardException {
        if (channel == null)
            throw new IllegalArgumentException("channel is null");

        // Try the default
        final CommandAPDU command = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 0x04, 0x00, 256);
        ResponseAPDU response = channel.transmit(command);

        // Unfused JCOP replies with 0x6A82 to everything
        if (response.getSW() == 0x6A82) {
            // If it has the identification AID, it probably is an unfused JCOP
            byte[] identify_aid = HexUtils.hex2bin("A000000167413000FF");
            CommandAPDU identify = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 0x04, 0x00, identify_aid, 256);
            ResponseAPDU identify_resp = channel.transmit(identify);
            byte[] identify_data = identify_resp.getData();
            // Check the fuse state
            if (identify_data.length > 15) {
                if (identify_data[14] == 0x00) {
                    throw new GPException("Unfused JCOP detected");
                }
            }
        }

        // SmartJac UICC
        if (response.getSW() == 0x6A87) {
            // Try the default
            logger.debug("Trying default ISD AID ...");
            return connect(channel, new AID(GPData.defaultISDBytes));
        }

        // 6283 - locked. Pass through locked.
        GPException.check(response, "Could not SELECT default selected", 0x6283);

        // Detect security domain based on default select
        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(response.getData());
        BerTlvLogger.log("    ", tlvs, GPData.getLoggerInstance());

        BerTlv fcitag = tlvs.find(new BerTag(0x6F));
        if (fcitag != null) {
            BerTlv isdaid = fcitag.find(new BerTag(0x84));
            // XXX: exists a card that returns a zero length AID in template
            if (isdaid != null && isdaid.getBytesValue().length > 0) {
                AID detectedAID = new AID(isdaid.getBytesValue());
                logger.debug("Auto-detected ISD: " + detectedAID);
                return new GlobalPlatform(channel, detectedAID);
            }
        }
        throw new GPDataException("Could not auto-detect ISD AID", response.getData());
    }

    // Establishes connection to a specific AID (selects it)
    public static GlobalPlatform connect(CardChannel channel, AID sdAID) throws CardException, GPException {
        if (channel == null) {
            throw new IllegalArgumentException("A card session is required");
        }
        if (sdAID == null) {
            throw new IllegalArgumentException("Security Domain AID is required");
        }

        logger.debug("(I)SD AID: " + sdAID);
        GlobalPlatform gp = new GlobalPlatform(channel, sdAID);
        gp.select(sdAID);
        return gp;
    }

    /**
     * Get the version and build information of the library.
     */
    public static String getVersion() {
        try (InputStream versionfile = GlobalPlatform.class.getResourceAsStream("pro_version.txt")) {
            String version = "unknown-development";
            if (versionfile != null) {
                try (BufferedReader vinfo = new BufferedReader(new InputStreamReader(versionfile, StandardCharsets.US_ASCII))) {
                    version = vinfo.readLine();
                }
            }
            return version;
        } catch (IOException e) {
            return "unknown-error";
        }
    }

    @Override
    public void close() throws Exception {
        // TODO explicitly closes SecureChannel, if connected.
    }

    public void setStrict(boolean strict) {
        this.strict = strict;
    }

    public void setBlockSize(int size) {
        this.blockSize = size;
    }

    public void setSpec(GPSpec spec) {
        this.spec = spec;
    }

    public AID getAID() {
        return new AID(sdAID.getBytes());
    }
    public CardChannel getCardChannel() { return channel; }

    protected void giveStrictWarning(String message) throws GPException {
        message = "STRICT WARNING: " + message;
        if (strict) {
            throw new GPException(message);
        } else {
            logger.warn(message);
        }
    }

    public int getScpKeyVersion() {
        return scpKeyVersion;
    }

    void select(AID sdAID) throws GPException, CardException {
        // Try to select ISD (default selected)
        final CommandAPDU command = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 0x04, 0x00, sdAID.getBytes(), 256);
        ResponseAPDU resp = channel.transmit(command);

        // If the ISD is locked, log it, but do not stop
        if (resp.getSW() == 0x6283) {
            logger.warn("SELECT ISD returned 6283 - CARD_LOCKED");
        }

        GPException.check(resp, "Could not SELECT Security Domain", 0x6283);
        parse_select_response(resp.getData());
    }

    private void parse_select_response(byte[] fci) throws GPException {
        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(fci);
        BerTlvLogger.log("    ", tlvs, GPData.getLoggerInstance());

        BerTlv fcitag = tlvs.find(new BerTag(0x6F));
        if (fcitag != null) {
            BerTlv isdaid = fcitag.find(new BerTag(0x84));
            if (isdaid != null) {
                AID detectedAID = new AID(isdaid.getBytesValue());
                if (!detectedAID.equals(sdAID)) {
                    giveStrictWarning(String.format("SD AID in FCI (%s) does not match the requested AID (%s)!", detectedAID, sdAID));
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
                        if (Arrays.equals(oidtag.getBytesValue(), HexUtils.hex2bin("2A864886FC6B01"))) {
                            // Detect versions
                            BerTlv vertag = isdd.find(new BerTag(0x60));
                            if (vertag != null) {
                                BerTlv veroid = vertag.find(new BerTag(0x06));
                                if (veroid != null) {
                                    spec = GPData.oid2version(veroid.getBytesValue());
                                    logger.debug("Auto-detected GP version: " + spec);
                                }
                            }
                        } else {
                            throw new GPDataException("Invalid CardRecognitionData", oidtag.getBytesValue());
                        }
                    } else {
                        logger.warn("Not global platform OID");
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

    private ResponseAPDU always_transmit(CommandAPDU cmd) throws CardException, GPException {
        if (wrapper != null) {
            return transmit(cmd);
        } else {
            return channel.transmit(cmd);
        }
    }

    // Assumes a selected SD
    public byte[] getKeyInfoTemplateBytes() throws CardException, GPException {
        CommandAPDU command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0xE0, 256);
        ResponseAPDU resp = always_transmit(command);

        if (resp.getSW() == ISO7816.SW_NO_ERROR) {
            return resp.getData();
        } else {
            logger.warn("GET DATA(Key Information Template) not supported");
            return new byte[0];
        }
    }

    public List<GPKey> getKeyInfoTemplate() throws CardException, GPException {
        List<GPKey> result = new ArrayList<>();
        result.addAll(GPData.get_key_template_list(getKeyInfoTemplateBytes()));
        return result;
    }

    public byte[] fetchCardData() throws CardException, GPException {
        // Card data
        CommandAPDU command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0x66, 256);
        ResponseAPDU resp = always_transmit(command);
        if (resp.getSW() == 0x6A86) {
            logger.debug("GET DATA(CardData) not supported, Open Platform 2.0.1 card? " + GPData.sw2str(resp.getSW()));
            return new byte[0];
        }
        // FIXME: JCOP SSD -  6A88
        if (resp.getSW() == ISO7816.SW_NO_ERROR) {
            return resp.getData();
        }
        return new byte[0];
    }

    public byte[] fetchCPLC() throws CardException, GPException {
        CommandAPDU command = new CommandAPDU(CLA_GP, INS_GET_DATA, 0x9F, 0x7F, 256);
        ResponseAPDU resp = channel.transmit(command);

        if (resp.getSW() == ISO7816.SW_NO_ERROR) {
            return resp.getData();
        } else {
            logger.warn("GET DATA(CPLC) failed: " + GPData.sw2str(resp.getSW()));
        }
        return new byte[0];
    }

    /**
     * Establishes a secure channel to the security domain.
     */
    public void openSecureChannel(GPSessionKeyProvider keys, byte[] host_challenge, int scpVersion, EnumSet<APDUMode> securityLevel)
            throws CardException, GPException {

        // ENC requires MAC
        if (securityLevel.contains(APDUMode.ENC)) {
            securityLevel.add(APDUMode.MAC);
        }

        // DWIM: Generate host challenge
        if (host_challenge == null) {
            host_challenge = new byte[8];
            GPCrypto.random.nextBytes(host_challenge);
            logger.trace("Generated host challenge: " + HexUtils.bin2hex(host_challenge));
        }

        // P1 key version (all)
        // P2 either key ID (SCP01) or 0 (SCP02)
        // TODO: use it here for KeyID?
        CommandAPDU initUpdate = new CommandAPDU(CLA_GP, INS_INITIALIZE_UPDATE, keys.getVersion(), scpVersion == 1 ? keys.getID() : 0, host_challenge, 256);

        ResponseAPDU response = channel.transmit(initUpdate);
        int sw = response.getSW();

        // Detect and report locked cards in a more sensible way.
        if ((sw == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED) || (sw == ISO7816.SW_AUTHENTICATION_METHOD_BLOCKED)) {
            throw new GPException(sw, "INITIALIZE UPDATE failed, card LOCKED?");
        }

        // Detect all other errors
        GPException.check(response, "INITIALIZE UPDATE failed");
        byte[] update_response = response.getData();

        // Verify response length (SCP01/SCP02 + SCP03 + SCP03 w/ pseudorandom)
        if (update_response.length != 28 && update_response.length != 29 && update_response.length != 32) {
            throw new GPException("Invalid INITIALIZE UPDATE response length: " + update_response.length);
        }
        // Parse the response
        int offset = 0;
        byte[] diversification_data = Arrays.copyOfRange(update_response, 0, 10);
        kdd = diversification_data;
        offset += diversification_data.length;
        // Get used key version from response
        scpKeyVersion = update_response[offset] & 0xFF;
        offset++;
        // Get major SCP version from Key Information field in response
        scpMajorVersion = update_response[offset];
        offset++;

        // get the protocol "i" parameter, if SCP03
        int scp_i = -1;
        if (scpMajorVersion == 3) {
            scp_i = update_response[offset];
            offset++;
        }

        // FIXME: SCP02 has 2 byte sequence + 6 bytes card challenge but the challenge is discarded ?
        // get card challenge
        byte card_challenge[] = Arrays.copyOfRange(update_response, offset, offset + 8);
        offset += card_challenge.length;
        // get card cryptogram
        byte card_cryptogram[] = Arrays.copyOfRange(update_response, offset, offset + 8);
        offset += card_cryptogram.length;

        logger.debug("Host challenge: " + HexUtils.bin2hex(host_challenge));
        logger.debug("Card challenge: " + HexUtils.bin2hex(card_challenge));
        logger.debug("Card reports SCP0{}{} with key version {}", scpMajorVersion, (scpMajorVersion == 3 ? " i=" + String.format("%02x", scp_i) : ""), String.format("%d (0x%02X)", scpKeyVersion, scpKeyVersion));

        // Verify response
        // If using explicit key version, it must match.
        if ((keys.getVersion() > 0) && (scpKeyVersion != keys.getVersion())) {
            throw new GPException("Key version mismatch: " + keys.getVersion() + " != " + scpKeyVersion);
        }

        // FIXME: the whole SCP vs variants thing is broken in API and implementation
        // Set default SCP version based on major version, if not explicitly known.
        if (scpVersion != scpMajorVersion && scpVersion != SCP_ANY) {
            logger.debug("Overriding SCP version: card reports " + scpMajorVersion + " but user requested " + scpVersion);
            scpMajorVersion = scpVersion;
        }

        // Set version for SC wrappers
        if (scpMajorVersion == 1) {
            scpVersion = SCP_01_05;
        } else if (scpMajorVersion == 2) {
            scpVersion = SCP_02_15;
        } else if (scpMajorVersion == 3) {
            scpVersion = 3; // FIXME: the symbolic numbering of versions needs to be fixed.
        }
        logger.debug("Will do SCP0{} ({})", scpMajorVersion, scpVersion);

        // Remove RMAC if SCP01 TODO: this should be generic sanitizer somewhere
        if (scpMajorVersion == 1 && securityLevel.contains(APDUMode.RMAC)) {
            logger.debug("SCP01 does not support RMAC, removing.");
            securityLevel.remove(APDUMode.RMAC);
        }

        // Extract ssc
        byte[] seq = null;
        if (scpMajorVersion == 2) {
            seq = Arrays.copyOfRange(update_response, 12, 14);
        } else if (scpMajorVersion == 3) {
            if (update_response.length == 32) {
                seq = Arrays.copyOfRange(update_response, 29, 32);
            }
        }

        // Calculate session keys
        keys.calculate(scpMajorVersion, diversification_data, host_challenge, card_challenge, seq);

        // Verify card cryptogram
        byte[] my_card_cryptogram = null;
        byte[] cntx = GPUtils.concatenate(host_challenge, card_challenge);
        if (scpMajorVersion == 1 || scpMajorVersion == 2) {
            my_card_cryptogram = GPCrypto.mac_3des_nulliv(keys.getKeyFor(GPSessionKeyProvider.KeyPurpose.ENC), cntx);
        } else {
            my_card_cryptogram = GPCrypto.scp03_kdf(keys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC), (byte) 0x00, cntx, 64);
        }

        // This is the main check for possible successful authentication.
        if (!Arrays.equals(card_cryptogram, my_card_cryptogram)) {
            if (System.console() != null) {
                // FIXME: this should be possible from GPTool
                System.err.println("Read more from https://github.com/martinpaljak/GlobalPlatformPro/wiki/Keys");
            }
            giveStrictWarning("Card cryptogram invalid!\nCard: " + HexUtils.bin2hex(card_cryptogram) + "\nHost: " + HexUtils.bin2hex(my_card_cryptogram) + "\n!!! DO NOT RE-TRY THE SAME COMMAND/KEYS OR YOU MAY BRICK YOUR CARD !!!");
        } else {
            logger.debug("Verified card cryptogram: " + HexUtils.bin2hex(my_card_cryptogram));
        }

        // Calculate host cryptogram and initialize SCP wrapper
        byte[] host_cryptogram = null;
        if (scpMajorVersion == 1 || scpMajorVersion == 2) {
            host_cryptogram = GPCrypto.mac_3des_nulliv(keys.getKeyFor(GPSessionKeyProvider.KeyPurpose.ENC), GPUtils.concatenate(card_challenge, host_challenge));
            wrapper = new SCP0102Wrapper(keys, scpVersion, EnumSet.of(APDUMode.MAC), null, null, blockSize);
        } else {
            host_cryptogram = GPCrypto.scp03_kdf(keys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC), (byte) 0x01, cntx, 64);
            wrapper = new SCP03Wrapper(keys, scpVersion, EnumSet.of(APDUMode.MAC), null, null, blockSize);
        }

        logger.debug("Calculated host cryptogram: " + HexUtils.bin2hex(host_cryptogram));
        int P1 = APDUMode.getSetValue(securityLevel);
        CommandAPDU externalAuthenticate = new CommandAPDU(CLA_MAC, ISO7816.INS_EXTERNAL_AUTHENTICATE_82, P1, 0, host_cryptogram);
        response = transmit(externalAuthenticate);
        GPException.check(response, "External authenticate failed");

        // Store reference for commands
        sessionKeys = keys;
        wrapper.setSecurityLevel(securityLevel);

        // FIXME: ugly stuff, ugly...
        if (scpMajorVersion != 3) {
            SCP0102Wrapper w = (SCP0102Wrapper) wrapper;
            if (securityLevel.contains(APDUMode.RMAC)) {
                w.setRMACIV(w.getIV());
            }
        }
    }

    public ResponseAPDU transmit(CommandAPDU command) throws CardException, GPException {
        CommandAPDU wc = wrapper.wrap(command);
        ResponseAPDU wr = channel.transmit(wc);
        return wrapper.unwrap(wr);
    }

    public int getSCPVersion() {
        return scpMajorVersion;
    }

    public void loadCapFile(CAPFile cap) throws CardException, GPException {
        loadCapFile(cap, false, false, false, false);
    }

    private void loadCapFile(CAPFile cap, boolean includeDebug, boolean separateComponents, boolean loadParam, boolean useHash)
            throws GPException, CardException {

        if (getRegistry().allAIDs().contains(cap.getPackageAID())) {
            giveStrictWarning("Package with AID " + cap.getPackageAID() + " is already present on card");
        }
        byte[] hash = useHash ? cap.getLoadFileDataHash("SHA1", includeDebug) : new byte[0];
        int len = cap.getCodeLength(includeDebug);
        // FIXME: parameters are optional for load
        byte[] loadParams = loadParam ? new byte[]{(byte) 0xEF, 0x04, (byte) 0xC6, 0x02, (byte) ((len & 0xFF00) >> 8),
                (byte) (len & 0xFF)} : new byte[0];

        ByteArrayOutputStream bo = new ByteArrayOutputStream();

        try {
            bo.write(cap.getPackageAID().getLength());
            bo.write(cap.getPackageAID().getBytes());

            bo.write(sdAID.getLength());
            bo.write(sdAID.getBytes());

            bo.write(hash.length);
            bo.write(hash);

            bo.write(loadParams.length);
            bo.write(loadParams);
            bo.write(0);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        CommandAPDU installForLoad = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, bo.toByteArray());
        ResponseAPDU response = transmit(installForLoad);
        GPException.check(response, "Install for Load failed");

        List<byte[]> blocks = cap.getLoadBlocks(includeDebug, separateComponents, wrapper.getBlockSize());
        for (int i = 0; i < blocks.size(); i++) {
            CommandAPDU load = new CommandAPDU(CLA_GP, INS_LOAD, (i == (blocks.size() - 1)) ? 0x80 : 0x00, (byte) i, blocks.get(i));
            response = transmit(load);
            GPException.check(response, "LOAD failed");
        }
        // Mark the registry as dirty
        dirty = true;
    }

    /**
     * Install an applet and make it selectable. The package and applet AID must
     * be present (ie. non-null). If one of the other parameters is null
     * sensible defaults are chosen. If installation parameters are used, they
     * must be passed in a special format, see parameter description below.
     * <p>
     * Before installation the package containing the applet must be loaded onto
     * the card, see {@link #loadCapFile loadCapFile}.
     * <p>
     * This method installs just one applet. Call it several times for packages
     * containing several applets.
     *
     * @param packageAID    the package that containing the applet
     * @param appletAID     the applet to be installed
     * @param instanceAID   the applet AID passed to the install method of the applet,
     *                      defaults to {@code packageAID} if null
     * @param privileges    privileges encoded as byte
     * @param installParams tagged installation parameters, defaults to {@code 0xC9 00}
     *                      (ie. no installation parameters) if null, if non-null the
     *                      format is {@code 0xC9 len data...}
     */
    @Deprecated
    public void installAndMakeSelectable(AID packageAID, AID appletAID, AID instanceAID, byte privileges, byte[] installParams,
                                         byte[] installToken) throws GPException, CardException {

        installAndMakeSelectable(packageAID, appletAID, instanceAID, Privileges.fromByte(privileges), installParams, installToken);
    }

    public void installAndMakeSelectable(AID packageAID, AID appletAID, AID instanceAID, Privileges privileges, byte[] installParams, byte[] installToken) throws GPException, CardException {

        if (instanceAID == null) {
            instanceAID = appletAID;
        }
        if (getRegistry().allAppletAIDs().contains(instanceAID)) {
            giveStrictWarning("Instance AID " + instanceAID + " is already present on card");
        }
        if (installParams == null) {
            installParams = new byte[]{(byte) 0xC9, 0x00};
        }
        if (installToken == null) {
            installToken = new byte[0];
        }
        byte[] privs = privileges.toBytes();
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

            bo.write(installParams.length);
            bo.write(installParams);

            bo.write(installToken.length);
            bo.write(installToken);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        CommandAPDU install = new CommandAPDU(CLA_GP, INS_INSTALL, 0x0C, 0x00, bo.toByteArray());
        ResponseAPDU response = transmit(install);
        GPException.check(response, "Install for Install and make selectable failed");
        dirty = true;
    }

    /**
     * Sends STORE DATA commands to the application identified
     *
     * @param aid - AID of the target application (or Security Domain)
     * @throws GPException
     * @throws CardException
     */
    public void storeData(AID aid, byte[] data) throws CardException, GPException {
        storeData(aid, data, (byte) 0x80);
    }

    /**
     * Sends STORE DATA commands to the application identified
     *
     * @param aid - AID of the target application (or Security Domain)
     * @throws GPException
     * @throws CardException
     */
    public void storeData(AID aid, byte[] data, byte P1) throws CardException, GPException {
        // send the INSTALL for personalization command
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            // GP 2.1.1 9.5.2.3.5
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
        CommandAPDU install = new CommandAPDU(CLA_GP, INS_INSTALL, 0x20, 0x00, bo.toByteArray());
        ResponseAPDU response = transmit(install);
        GPException.check(response, "Install for personalization failed");

        // Now pump the data
        List<byte[]> blocks = GPUtils.splitArray(data, wrapper.getBlockSize());
        for (int i = 0; i < blocks.size(); i++) {
            CommandAPDU load = new CommandAPDU(CLA_GP, INS_STORE_DATA, (i == (blocks.size() - 1)) ? P1 : 0x00, (byte) i, blocks.get(i));
            response = transmit(load);
            GPException.check(response, "STORE DATA failed");
        }
    }

    public void makeDefaultSelected(AID aid) throws CardException, GPException {
        // FIXME: only works for some 2.1.1 cards ? Clarify and document
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        // Only supported privilege.
        Privileges ds = Privileges.set(Privilege.CardReset);
        byte privileges = ds.toByte();

        try {
            bo.write(0);
            bo.write(0);
            bo.write(aid.getLength());
            bo.write(aid.getBytes());
            bo.write(1);
            bo.write(privileges);
            bo.write(0);
            bo.write(0);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        CommandAPDU install = new CommandAPDU(CLA_GP, INS_INSTALL, 0x08, 0x00, bo.toByteArray());
        ResponseAPDU response = transmit(install);
        GPException.check(response, "Install for make selectable failed");
        dirty = true;
    }

    public void lockUnlockApplet(AID app, boolean lock) throws CardException, GPException {
        CommandAPDU cmd = new CommandAPDU(CLA_GP, INS_SET_STATUS, 0x40, lock ? 0x80 : 0x00, app.getBytes());
        ResponseAPDU response = transmit(cmd);
        GPException.check(response, "SET STATUS failed");
        dirty = true;
    }

    public void setCardStatus(byte status) throws CardException, GPException {
        logger.debug("Setting status to {}", GPRegistryEntry.getLifeCycleString(Kind.IssuerSecurityDomain, status));
        CommandAPDU cmd = new CommandAPDU(CLA_GP, INS_SET_STATUS, 0x80, status);
        ResponseAPDU response = transmit(cmd);
        GPException.check(response, "SET STATUS failed");
        dirty = true;
    }

    /**
     * Delete file {@code aid} on the card. Delete dependencies as well if
     * {@code deleteDeps} is true.
     *
     * @param aid        identifier of the file to delete
     * @param deleteDeps if true delete dependencies as well
     * @throws CardException for low-level communication errors
     */
    public void deleteAID(AID aid, boolean deleteDeps) throws GPException, CardException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            bo.write(0x4f);
            bo.write(aid.getLength());
            bo.write(aid.getBytes());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        CommandAPDU delete = new CommandAPDU(CLA_GP, INS_DELETE, 0x00, deleteDeps ? 0x80 : 0x00, bo.toByteArray());
        ResponseAPDU response = transmit(delete);
        GPException.check(response, "Deletion failed");
        dirty = true;
    }

    public void deleteKey(int keyver) throws GPException, CardException {
        // FIXME: no card seems to support it
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        //bo.write(0xd0);
        //bo.write(1);
        bo.write(0xd2);
        bo.write(keyver);

//		bo.write(0xd0);
//		bo.write(2);
//		bo.write(0xd2);
//		bo.write(keyver);
//
//		bo.write(0xd0);
//		bo.write(3);
//		bo.write(0xd2);
//		bo.write(keyver);
        CommandAPDU delete = new CommandAPDU(CLA_GP, INS_DELETE, 0x00, 0x00, bo.toByteArray());
        ResponseAPDU response = transmit(delete);
        GPException.check(response, "Deletion failed");
    }

    public void renameISD(AID newaid) throws GPException, CardException {
        CommandAPDU rename = new CommandAPDU(CLA_GP, INS_STORE_DATA, 0x90, 0x00, GPUtils.concatenate(new byte[]{0x4f, (byte) newaid.getLength()}, newaid.getBytes()));
        ResponseAPDU response = transmit(rename);
        GPException.check(response, "Rename failed");
    }

    // FIXME: remove the withCheck parameter, as always true?
    private byte[] encodeKey(GPKey key, GPKey dek, boolean withCheck) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            if (key.getType() == Type.DES3) {
                // Encrypt key with DEK
                Cipher cipher;
                cipher = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, dek.getKeyAs(Type.DES3));
                byte[] cgram = cipher.doFinal(key.getBytes(), 0, 16);
                baos.write(0x80); // 3DES
                baos.write(cgram.length); // Length
                baos.write(cgram);
                if (withCheck) {
                    byte[] kcv = GPCrypto.kcv_3des(key);
                    baos.write(kcv.length);
                    baos.write(kcv);
                } else {
                    baos.write(0);
                }
            } else if (key.getType() == Type.AES) {
                //	baos.write(0xFF);
                byte[] cgram = GPCrypto.scp03_encrypt_key(dek, key);
                byte[] check = GPCrypto.scp03_key_check_value(key);
                baos.write(0x88); // AES
                baos.write(cgram.length + 1);
                baos.write(key.getLength());
                baos.write(cgram);
                baos.write(check.length);
                baos.write(check);
            } else {
                throw new IllegalArgumentException("Don't know how to handle " + key.getType());
            }
            return baos.toByteArray();
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public void putKeys(List<GPKey> keys, boolean replace, PlaintextKeys.Diversification diversifier) throws GPException, CardException {
        if(diversifier != null){
            GPKey key= keys.get(0);
            keys.clear();
            keys.add(new GPKey(key.getVersion(), 1,diversify(key, GPSessionKeyProvider.KeyPurpose.ENC, kdd,diversifier)));
            keys.add(new GPKey(key.getVersion(), 2,diversify(key, GPSessionKeyProvider.KeyPurpose.MAC, kdd,diversifier)));
            keys.add(new GPKey(key.getVersion(), 3,diversify(key, GPSessionKeyProvider.KeyPurpose.DEK, kdd,diversifier)));
        }
        // Check for sanity and usability
        if (keys.size() < 1 || keys.size() > 3) {
            throw new IllegalArgumentException("Can add 1 or up to 3 keys at a time");
        }
        if (keys.size() > 1) {
            for (int i = 1; i < keys.size(); i++) {
                if (keys.get(i - 1).getID() != keys.get(i).getID() - 1) {
                    throw new IllegalArgumentException("Key ID-s of multiple keys must be sequential!");
                }
            }
        }

        // Log and trace
        logger.debug("PUT KEY version {}", keys.get(0).getVersion());
        for (GPKey k : keys) {
            logger.trace("PUT KEY:" + k);
        }
        // Check consistency, if template is available.
        List<GPKey> tmpl = getKeyInfoTemplate();

        if (tmpl.size() > 0) {
            if ((tmpl.get(0).getVersion() < 1 || tmpl.get(0).getVersion() > 0x7F) && replace) {
                giveStrictWarning("Trying to replace factory keys, when you need to add new ones? Is this a virgin card? (use --virgin)");
            }

            // Check if key types and lengths are the same when replacing
            if (replace && (keys.get(0).getType() != tmpl.get(0).getType() || keys.get(0).getLength() != tmpl.get(0).getLength())) {
                // FIXME: SCE60 template has 3DES keys but uses AES.
                giveStrictWarning("Can not replace keys of different type or size: " + tmpl.get(0).getType() + "->" + keys.get(0).getType());
            }

            // Check for matching version numbers if replacing and vice versa
            if (!replace && (keys.get(0).getVersion() == tmpl.get(0).getVersion())) {
                throw new IllegalArgumentException("Not adding keys and version matches existing?");
            }

            if (replace && (keys.get(0).getVersion() != tmpl.get(0).getVersion())) {
                throw new IllegalArgumentException("Replacing keys and versions don't match existing?");
            }
        } else {
            if (replace) {
                logger.warn("No key template on card but trying to replace. Implying add");
                replace = false;
            }
        }

        // Construct APDU
        int P1 = 0x00; // New key in single command unless replace
        if (replace) {
            P1 = keys.get(0).getVersion();
        }
        int P2 = keys.get(0).getID();
        if (keys.size() > 1) {
            P2 |= 0x80;
        }
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            // New key version
            bo.write(keys.get(0).getVersion());
            // Key data

            bo.write(encodeKey(keys.get(0), sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.DEK), true));
            bo.write(encodeKey(keys.get(1), sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.DEK), true));
            bo.write(encodeKey(keys.get(2), sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.DEK), true));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        CommandAPDU command = new CommandAPDU(CLA_GP, INS_PUT_KEY, P1, P2, bo.toByteArray());
        ResponseAPDU response = transmit(command);
        GPException.check(response, "PUT KEY failed");
    }

    public GPRegistry getRegistry() throws GPException, CardException {
        if (dirty) {
            registry = getStatus();
            dirty = false;
        }
        return registry;
    }

    // TODO: The way registry parsing mode is piggybacked to the registry class is not really nice.
    private byte[] getConcatenatedStatus(GPRegistry reg, int p1, byte[] data) throws CardException, GPException {
        // By default use tags
        int p2 = reg.tags ? 0x02 : 0x00;

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
                reg.tags = false;
                return getConcatenatedStatus(reg, p1, data);
            }
        }

        int sw = response.getSW();
        if ((sw != ISO7816.SW_NO_ERROR) && (sw != 0x6310)) {
            // Possible values:
            if (sw == 0x6A88) {
                // No data to report
                return response.getData();

            }
            // 0x6A86 - no tags support or ISD asked from SSD
            // 0a6A81 - Same as 6A88 ?
            logger.warn("GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()) + " with " + GPData.sw2str(response.getSW()));
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

    private GPRegistry getStatus() throws CardException, GPException {
        GPRegistry registry = new GPRegistry();

        if (spec == GPSpec.OP201) {
            registry.tags = false;
        }
        // Issuer security domain
        byte[] data = getConcatenatedStatus(registry, 0x80, new byte[]{0x4F, 0x00});
        registry.parse(0x80, data, Kind.IssuerSecurityDomain, spec);

        // Apps and security domains
        data = getConcatenatedStatus(registry, 0x40, new byte[]{0x4F, 0x00});
        registry.parse(0x40, data, Kind.Application, spec);

        // Load files
        data = getConcatenatedStatus(registry, 0x20, new byte[]{0x4F, 0x00});
        registry.parse(0x20, data, Kind.ExecutableLoadFile, spec);

        if (spec != GPSpec.OP201) { // TODO: remove
            // Load files with modules
            data = getConcatenatedStatus(registry, 0x10, new byte[]{0x4F, 0x00});
            registry.parse(0x10, data, Kind.ExecutableLoadFile, spec);
        }
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


    public enum GPSpec {OP201, GP211, GP22}

    static class SCP0102Wrapper extends SCPWrapper {

        private final ByteArrayOutputStream rMac = new ByteArrayOutputStream();
        private byte[] icv = null;
        private byte[] ricv = null;
        private int scp = 0;
        private boolean icvEnc = false;

        private boolean preAPDU = false;
        private boolean postAPDU = false;


        private SCP0102Wrapper(GPSessionKeyProvider sessionKeys, int scp, EnumSet<APDUMode> securityLevel, byte[] icv, byte[] ricv, int bs) {
            this.blockSize = bs;
            this.sessionKeys = sessionKeys;
            this.icv = icv;
            this.ricv = ricv;
            setSCPVersion(scp);
            setSecurityLevel(securityLevel);
        }

        private static byte clearBits(byte b, byte mask) {
            return (byte) ((b & ~mask) & 0xFF);
        }

        private static byte setBits(byte b, byte mask) {
            return (byte) ((b | mask) & 0xFF);
        }

        public void setSCPVersion(int scp) {
            // Major version of wrapper
            this.scp = 2;
            if (scp < SCP_02_04) {
                this.scp = 1;
            }

            // modes
            if ((scp == SCP_01_15) || (scp == SCP_02_14) || (scp == SCP_02_15) || (scp == SCP_02_1A) || (scp == SCP_02_1B)) {
                icvEnc = true;
            } else {
                icvEnc = false;
            }
            if ((scp == SCP_01_05) || (scp == SCP_01_15) || (scp == SCP_02_04) || (scp == SCP_02_05) || (scp == SCP_02_14) || (scp == SCP_02_15)) {
                preAPDU = true;
            } else {
                preAPDU = false;
            }
            if ((scp == SCP_02_0A) || (scp == SCP_02_0B) || (scp == SCP_02_1A) || (scp == SCP_02_1B)) {
                postAPDU = true;
            } else {
                postAPDU = false;
            }
        }

        public byte[] getIV() {
            return icv;
        }

        public void setRMACIV(byte[] iv) {
            ricv = iv;
        }

        public CommandAPDU wrap(CommandAPDU command) throws GPException {

            try {
                if (rmac) {
                    rMac.reset();
                    rMac.write(clearBits((byte) command.getCLA(), (byte) 0x07));
                    rMac.write(command.getINS());
                    rMac.write(command.getP1());
                    rMac.write(command.getP2());
                    if (command.getNc() >= 0) {
                        rMac.write(command.getNc());
                        rMac.write(command.getData());
                    }
                }
                if (!mac && !enc) {
                    return command;
                }


                int origCLA = command.getCLA();
                int newCLA = origCLA;
                int origINS = command.getINS();
                int origP1 = command.getP1();
                int origP2 = command.getP2();
                byte[] origData = command.getData();
                int origLc = command.getNc();
                int newLc = origLc;
                byte[] newData = null;
                int le = command.getNe();
                ByteArrayOutputStream t = new ByteArrayOutputStream();

                if (origLc > getBlockSize()) {
                    throw new IllegalArgumentException("APDU too long for wrapping.");
                }

                if (mac) {
                    if (icv == null) {
                        icv = new byte[8];
                    } else if (icvEnc) {
                        Cipher c = null;
                        if (scp == 1) {
                            c = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
                            c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC).getKeyAs(Type.DES3));
                        } else {
                            c = Cipher.getInstance(GPCrypto.DES_ECB_CIPHER);
                            c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC).getKeyAs(Type.DES));
                        }
                        // encrypts the future ICV ?
                        icv = c.doFinal(icv);
                    }

                    if (preAPDU) {
                        newCLA = setBits((byte) newCLA, (byte) 0x04);
                        newLc = newLc + 8;
                    }
                    t.write(newCLA);
                    t.write(origINS);
                    t.write(origP1);
                    t.write(origP2);
                    t.write(newLc);
                    t.write(origData);

                    if (scp == 1) {
                        icv = GPCrypto.mac_3des(sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC), t.toByteArray(), icv);
                    } else if (scp == 2) {
                        icv = GPCrypto.mac_des_3des(sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC), t.toByteArray(), icv);
                    }

                    if (postAPDU) {
                        newCLA = setBits((byte) newCLA, (byte) 0x04);
                        newLc = newLc + 8;
                    }
                    t.reset();
                    newData = origData;
                }

                if (enc && (origLc > 0)) {
                    if (scp == 1) {
                        t.write(origLc);
                        t.write(origData);
                        if ((t.size() % 8) != 0) {
                            byte[] x = GPCrypto.pad80(t.toByteArray(), 8);
                            t.reset();
                            t.write(x);
                        }
                    } else {
                        t.write(GPCrypto.pad80(origData, 8));
                    }
                    newLc += t.size() - origData.length;

                    Cipher c = Cipher.getInstance(GPCrypto.DES3_CBC_CIPHER);
                    c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.ENC).getKeyAs(Type.DES3), GPCrypto.iv_null_8);
                    newData = c.doFinal(t.toByteArray());
                    t.reset();
                }
                t.write(newCLA);
                t.write(origINS);
                t.write(origP1);
                t.write(origP2);
                if (newLc > 0) {
                    t.write(newLc);
                    t.write(newData);
                }
                if (mac) {
                    t.write(icv);
                }
                if (le > 0) {
                    t.write(le);
                }
                CommandAPDU wrapped = new CommandAPDU(t.toByteArray());
                return wrapped;
            } catch (IOException e) {
                throw new RuntimeException("APDU wrapping failed", e);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new IllegalStateException("APDU wrapping failed", e);
            } catch (GeneralSecurityException e) {
                throw new GPException("APDU wrapping failed", e);
            }
        }

        public ResponseAPDU unwrap(ResponseAPDU response) throws GPException {
            if (rmac) {
                if (response.getData().length < 8) {
                    throw new RuntimeException("Wrong response length (too short).");
                }
                int respLen = response.getData().length - 8;
                rMac.write(respLen);
                rMac.write(response.getData(), 0, respLen);
                rMac.write(response.getSW1());
                rMac.write(response.getSW2());

                ricv = GPCrypto.mac_des_3des(sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.RMAC), GPCrypto.pad80(rMac.toByteArray(), 8), ricv);

                byte[] actualMac = new byte[8];
                System.arraycopy(response.getData(), respLen, actualMac, 0, 8);
                if (!Arrays.equals(ricv, actualMac)) {
                    throw new GPException("RMAC invalid.");
                }
                ByteArrayOutputStream o = new ByteArrayOutputStream();
                o.write(response.getBytes(), 0, respLen);
                o.write(response.getSW1());
                o.write(response.getSW2());
                response = new ResponseAPDU(o.toByteArray());
            }
            return response;
        }
    }

    // FIXME - extract classes
    static class SCP03Wrapper extends SCPWrapper {
        // Both are block size length
        byte[] chaining_value = new byte[16];
        byte[] encryption_counter = new byte[16];

        private SCP03Wrapper(GPSessionKeyProvider sessionKeys, int scp, EnumSet<APDUMode> securityLevel, byte[] icv, byte[] ricv, int bs) {
            this.sessionKeys = sessionKeys;
            this.blockSize = bs;
            // initialize chaining value.
            System.arraycopy(GPCrypto.null_bytes_16, 0, chaining_value, 0, GPCrypto.null_bytes_16.length);
            // initialize encryption counter.
            System.arraycopy(GPCrypto.null_bytes_16, 0, encryption_counter, 0, GPCrypto.null_bytes_16.length);
            setSecurityLevel(securityLevel);
        }

        @Override
        protected CommandAPDU wrap(CommandAPDU command) throws GPException {
            byte[] cmd_mac = null;

            try {
                int cla = command.getCLA();
                int lc = command.getNc();
                byte[] data = command.getData();

                // Encrypt if needed
                if (enc) {
                    cla = 0x84;
                    // Counter shall always be incremented
                    GPCrypto.buffer_increment(encryption_counter);
                    if (command.getData().length > 0) {
                        byte[] d = GPCrypto.pad80(command.getData(), 16);
                        // Encrypt with S-ENC, after increasing the counter
                        Cipher c = Cipher.getInstance(GPCrypto.AES_CBC_CIPHER);
                        c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.ENC).getKeyAs(Type.AES), GPCrypto.iv_null_16);
                        byte[] iv = c.doFinal(encryption_counter);
                        // Now encrypt the data with S-ENC.
                        c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.ENC).getKeyAs(Type.AES), new IvParameterSpec(iv));
                        data = c.doFinal(d);
                        lc = data.length;
                    }
                }
                // Calculate C-MAC
                if (mac) {
                    cla = 0x84;
                    lc = lc + 8;

                    ByteArrayOutputStream bo = new ByteArrayOutputStream();
                    bo.write(chaining_value);
                    bo.write(cla);
                    bo.write(command.getINS());
                    bo.write(command.getP1());
                    bo.write(command.getP2());
                    bo.write(lc);
                    bo.write(data);
                    byte[] cmac_input = bo.toByteArray();
                    byte[] cmac = GPCrypto.scp03_mac(sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC), cmac_input, 128);
                    // Set new chaining value
                    System.arraycopy(cmac, 0, chaining_value, 0, chaining_value.length);
                    // 8 bytes for actual mac
                    cmd_mac = Arrays.copyOf(cmac, 8);
                }
                // Construct new command
                ByteArrayOutputStream na = new ByteArrayOutputStream();
                na.write(cla); // possibly fiddled
                na.write(command.getINS());
                na.write(command.getP1());
                na.write(command.getP2());
                na.write(lc);
                na.write(data);
                if (mac)
                    na.write(cmd_mac);
                if (command.getNe() > 0) {
                    na.write(command.getNe());
                }
                byte[] new_apdu = na.toByteArray();
                return new CommandAPDU(new_apdu);
            } catch (IOException e) {
                throw new RuntimeException("APDU wrapping failed", e);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new IllegalStateException("APDU wrapping failed", e);
            } catch (GeneralSecurityException e) {
                throw new GPException("APDU wrapping failed", e);
            }
        }

        @Override
        protected ResponseAPDU unwrap(ResponseAPDU response) throws GPException {
            try {
                if (rmac) {
                    if (response.getData().length < 8) {
                        throw new RuntimeException("Wrong response length (too short)."); // FIXME: bad exception
                    }
                    int respLen = response.getData().length - 8;

                    byte[] actualMac = new byte[8];
                    System.arraycopy(response.getData(), respLen, actualMac, 0, 8);

                    ByteArrayOutputStream bo = new ByteArrayOutputStream();
                    bo.write(chaining_value);
                    bo.write(response.getData(), 0, respLen);
                    bo.write(response.getSW1());
                    bo.write(response.getSW2());

                    byte[] cmac_input = bo.toByteArray();

                    byte[] cmac = GPCrypto.scp03_mac(sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.RMAC), cmac_input, 128);

                    // 8 bytes for actual mac
                    byte[] resp_mac = Arrays.copyOf(cmac, 8);

                    if (!Arrays.equals(resp_mac, actualMac)) {
                        throw new GPException("RMAC invalid: " + HexUtils.bin2hex(actualMac) + " vs " + HexUtils.bin2hex(resp_mac));
                    }

                    ByteArrayOutputStream o = new ByteArrayOutputStream();
                    o.write(response.getBytes(), 0, respLen);
                    o.write(response.getSW1());
                    o.write(response.getSW2());
                    response = new ResponseAPDU(o.toByteArray());
                }
                if (renc) {
                    // Encrypt with S-ENC, after changing the first byte of the counter
                    byte [] response_encryption_counter = Arrays.copyOf(encryption_counter, encryption_counter.length);
                    response_encryption_counter[0] = (byte) 0x80;
                    Cipher c = Cipher.getInstance(GPCrypto.AES_CBC_CIPHER);
                    c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.ENC).getKeyAs(Type.AES), GPCrypto.iv_null_16);
                    byte[] iv = c.doFinal(response_encryption_counter);
                    // Now decrypt the data with S-ENC, with the new IV
                    c.init(Cipher.DECRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.ENC).getKeyAs(Type.AES), new IvParameterSpec(iv));
                    byte[] data = c.doFinal(response.getData());
                    ByteArrayOutputStream o = new ByteArrayOutputStream();
                    o.write(GPCrypto.unpad80(data));
                    o.write(response.getSW1());
                    o.write(response.getSW2());
                    response = new ResponseAPDU(o.toByteArray());
                }
                return response;
            } catch (IOException e) {
                throw new RuntimeException("APDU unwrapping failed", e);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new IllegalStateException("APDU unwrapping failed", e);
            } catch (GeneralSecurityException e) {
                throw new GPException("APDU unwrapping failed", e);
            }
        }
    }

    static abstract class SCPWrapper {
        protected int blockSize = 0;
        protected GPSessionKeyProvider sessionKeys = null;
        protected boolean mac = false;
        protected boolean enc = false;
        protected boolean rmac = false;
        protected boolean renc = false;


        public void setSecurityLevel(EnumSet<APDUMode> securityLevel) {
            mac = securityLevel.contains(APDUMode.MAC);
            enc = securityLevel.contains(APDUMode.ENC);
            rmac = securityLevel.contains(APDUMode.RMAC);
            renc = securityLevel.contains(APDUMode.RENC);
        }

        protected int getBlockSize() {
            int res = this.blockSize;
            if (mac)
                res = res - 8;
            if (enc)
                res = res - 8;
            return res;
        }

        protected abstract CommandAPDU wrap(CommandAPDU command) throws GPException;

        protected abstract ResponseAPDU unwrap(ResponseAPDU response) throws GPException;
    }
}
