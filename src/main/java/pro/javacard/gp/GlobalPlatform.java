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
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.AID;
import pro.javacard.CAPFile;
import pro.javacard.gp.GPKey.Type;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPRegistryEntry.Privileges;

import javax.crypto.Cipher;
import javax.smartcardio.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * Represents a connection to a GlobalPlatform Card (BIBO interface)
 * Does secure channel and low-level translation of GP* objects to APDU-s and arguments
 * NOT thread-safe
 */
public class GlobalPlatform extends CardChannel implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(GlobalPlatform.class);

    private static final String LFDBH_SHA1 = "SHA1";
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

    public static final byte P1_INSTALL_AND_MAKE_SELECTABLE = (byte) 0x0C;
    public static final byte P1_INSTALL_FOR_INSTALL = (byte) 0x04;

    protected boolean strict = true;
    GPSpec spec = GPSpec.GP211;

    // (I)SD AID successfully selected or null
    private AID sdAID = null;
    // Either 1 or 2 or 3
    private int scpMajorVersion = 0;
    private int scpKeyVersion = 0;

    private int blockSize = 255;
    private GPSessionKeyProvider sessionKeys = null;
    private SecureChannelWrapper wrapper = null;
    private CardChannel channel;
    private GPRegistry registry = null;
    private boolean dirty = true; // True if registry is dirty.

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

        final BerTlvs tlvs;
        try {
            // Detect security domain based on default select
            BerTlvParser parser = new BerTlvParser();
            tlvs = parser.parse(response.getData());
            GPUtils.trace_tlv(response.getData(), logger);
        } catch (ArrayIndexOutOfBoundsException | IllegalStateException e) {
            // XXX: Exists a card, which returns plain AID as response
            logger.warn("Could not parse SELECT response: " + e.getMessage());
            throw new GPDataException("Could not auto-detect ISD AID", response.getData());
        }

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
    public void close() {
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

    public CardChannel getCardChannel() {
        return channel;
    }

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

    List<GPKey> getKeyInfoTemplate() throws CardException, GPException {
        List<GPKey> result = new ArrayList<>();
        result.addAll(GPData.get_key_template_list(GPData.fetchKeyInfoTemplate(this)));
        return result;
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

    // Exist to be able to pass around a transmit method
    @Override
    public Card getCard() {
        return null;
    }

    @Override
    public int getChannelNumber() {
        return 0;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU command) throws CardException {
        try {
            CommandAPDU wc = wrapper.wrap(command);
            ResponseAPDU wr = channel.transmit(wc);
            return wrapper.unwrap(wr);
        } catch (GPException e) {
            throw new CardException("Secure channel failure: " + e.getMessage(), e);
        }
    }

    private ResponseAPDU transmitLV(CommandAPDU command) throws CardException {
        logger.trace("Payload: ");
        GPUtils.trace_lv(command.getData(), logger);
        return transmit(command);
    }

    @Override
    public int transmit(ByteBuffer byteBuffer, ByteBuffer byteBuffer1) throws CardException {
        throw new IllegalStateException("Use the other transmit");
    }

    public int getSCPVersion() {
        return scpMajorVersion;
    }

    public void loadCapFile(CAPFile cap, AID target) throws CardException, GPException {
        if (target == null)
            target = sdAID;
        loadCapFile(cap, target, false, false, null, null, LFDBH_SHA1);
    }

    public void loadCapFile(CAPFile cap, AID target, byte[] dap, String hash) throws CardException, GPException {
        if (target == null)
            target = sdAID;
        loadCapFile(cap, target, false, false, target, dap, hash);
    }

    public void loadCapFile(CAPFile cap, AID target, AID dapdomain, byte[] dap, String hash) throws CardException, GPException {
        if (target == null)
            target = sdAID;
        loadCapFile(cap, target, false, false, dapdomain, dap, hash);
    }

    private void loadCapFile(CAPFile cap, AID sdaid, boolean includeDebug, boolean loadParam, AID dapdomain, byte[] dap, String lfdbh)
            throws GPException, CardException {

        if (getRegistry().allAIDs().contains(cap.getPackageAID())) {
            giveStrictWarning("Package with AID " + cap.getPackageAID() + " is already present on card");
        }

        // FIXME: hash type handling needs to be sensible.
        byte[] hash = dap != null ? cap.getLoadFileDataHash(lfdbh, includeDebug) : new byte[0];
        byte[] code = cap.getCode(includeDebug);
        // FIXME: parameters are optional for load
        byte[] loadParams = loadParam ? new byte[]{(byte) 0xEF, 0x04, (byte) 0xC6, 0x02, (byte) ((code.length & 0xFF00) >> 8),
                (byte) (code.length & 0xFF)} : new byte[0];

        ByteArrayOutputStream bo = new ByteArrayOutputStream();

        try {
            bo.write(cap.getPackageAID().getLength());
            bo.write(cap.getPackageAID().getBytes());

            bo.write(sdaid.getLength());
            bo.write(sdaid.getBytes());

            bo.write(hash.length); // Load File Data Block Hash
            bo.write(hash);

            bo.write(loadParams.length);
            bo.write(loadParams);
            bo.write(0); // Load token
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        CommandAPDU installForLoad = new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00, bo.toByteArray());
        ResponseAPDU response = transmitLV(installForLoad);
        GPException.check(response, "INSTALL [for load] failed");


        // Construct load block
        ByteArrayOutputStream loadblock = new ByteArrayOutputStream();
        try {
            // Add DAP block, if signature present
            if (dap != null) {
                loadblock.write(0xE2);
                loadblock.write(GPUtils.encodeLength(dapdomain.getLength() + dap.length + GPUtils.encodeLength(dap.length).length + 3)); // two tags, two lengths FIXME: proper size
                loadblock.write(0x4F);
                loadblock.write(dapdomain.getLength());
                loadblock.write(dapdomain.getBytes());
                loadblock.write(0xC3);
                loadblock.write(GPUtils.encodeLength(dap.length));
                loadblock.write(dap);
            }
            // See GP 2.1.1 Table 9-40, GP 2.2.1 11.6.2.3 / Table 11-58
            loadblock.write(0xC4);
            loadblock.write(GPUtils.encodeLength(code.length));
            loadblock.write(code);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Split according to available block size
        List<byte[]> blocks = GPUtils.splitArray(loadblock.toByteArray(), wrapper.getBlockSize());

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
     * @param privileges    privileges encoded as an object
     * @param installParams tagged installation parameters, defaults to {@code 0xC9 00}
     *                      (ie. no installation parameters) if null, if non-null the
     *                      format is {@code 0xC9 len data...}
     */
    public void installAndMakeSelectable(AID packageAID, AID appletAID, AID instanceAID, Privileges privileges, byte[] installParams, byte[] installToken) throws GPException, CardException {
        if (instanceAID == null) {
            instanceAID = appletAID;
        }
        if (getRegistry().allAppletAIDs().contains(instanceAID)) {
            giveStrictWarning("Instance AID " + instanceAID + " is already present on card");
        }

        byte[] data = buildInstallData(packageAID, appletAID, instanceAID, privileges, installParams, installToken);
        CommandAPDU install = new CommandAPDU(CLA_GP, INS_INSTALL, P1_INSTALL_AND_MAKE_SELECTABLE, 0x00, data);
        ResponseAPDU response = transmitLV(install);
        GPException.check(response, "INSTALL [for install and make selectable] failed");
        dirty = true;
    }

    /**
     * Install an applet. Do not make it selectable. The package and applet AID must
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
     * @param privileges    privileges encoded as an object
     * @param installParams tagged installation parameters, defaults to {@code 0xC9 00}
     *                      (ie. no installation parameters) if null, if non-null the
     *                      format is {@code 0xC9 len data...}
     */
    public void installForInstall(AID packageAID, AID appletAID, AID instanceAID, Privileges privileges, byte[] installParams, byte[] installToken) throws GPException, CardException {
        if (instanceAID == null) {
            instanceAID = appletAID;
        }
        if (getRegistry().allAppletAIDs().contains(instanceAID)) {
            giveStrictWarning("Instance AID " + instanceAID + " is already present on card");
        }

        byte[] data = buildInstallData(packageAID, appletAID, instanceAID, privileges, installParams, installToken);
        CommandAPDU install = new CommandAPDU(CLA_GP, INS_INSTALL, P1_INSTALL_FOR_INSTALL, 0x00, data);
        ResponseAPDU response = transmitLV(install);
        GPException.check(response, "INSTALL [for install] failed");
        dirty = true;
    }

    private byte[] buildInstallData(AID packageAID, AID appletAID, AID instanceAID, Privileges privileges, byte[] installParams, byte[] installToken) {
        if (instanceAID == null) {
            instanceAID = appletAID;
        }
        if (installParams == null || installParams.length == 0) {
            installParams = new byte[]{(byte) 0xC9, 0x00};
        }
        // Simple use: only application parameters without tag, prepend 0xC9
        if (installParams[0] != (byte) 0xC9) {
            byte[] newparams = new byte[installParams.length + 2];
            newparams[0] = (byte) 0xC9;
            newparams[1] = (byte) installParams.length;
            System.arraycopy(installParams, 0, newparams, 2, installParams.length);
            installParams = newparams;
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
        return bo.toByteArray();
    }

    public void extradite(AID what, AID to) throws GPException, CardException {
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
            bo.write(0x00); // no extradition token
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        CommandAPDU install = new CommandAPDU(CLA_GP, INS_INSTALL, 0x10, 0x00, bo.toByteArray());
        ResponseAPDU response = transmitLV(install);
        GPException.check(response, "INSTALL [for extradition] failed");
        dirty = true;
    }


    public void installForPersonalization(AID aid) throws CardException, GPException {
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


    public byte[] personalizeSingle(AID aid, byte[] data, int P1) throws CardException, GPException {
        return personalize(aid, Collections.singletonList(data), P1).get(0);
    }

    /**
     * Sends STORE DATA commands to the application identified via SD
     *
     * @param aid - AID of the target application (or Security Domain)
     * @throws GPException
     * @throws CardException
     */
    public void personalize(AID aid, byte[] data, int P1) throws CardException, GPException {
        installForPersonalization(aid);
        // Now pump the data
        storeData(data, P1);
    }


    public List<byte[]> personalize(AID aid, List<byte[]> data, int P1) throws CardException, GPException {
        installForPersonalization(aid);
        return storeData(data, P1);
    }


    public byte[] storeDataSingle(byte[] data, int P1) throws CardException, GPException {
        if (data.length > wrapper.getBlockSize()) {
            throw new IllegalArgumentException("block size is bigger than possibility to send: " + data.length + ">" + wrapper.getBlockSize());
        }
        return storeData(Collections.singletonList(data), P1).get(0);
    }

    // Send a GP-formatted STORE DATA block, splitting it into pieces if/as necessary
    public void storeData(byte[] data, int P1) throws CardException, GPException {
        List<byte[]> blocks = GPUtils.splitArray(data, wrapper.getBlockSize());
        storeData(blocks, P1);
    }

    // Send a GP-formatted STORE DATA blocks
    public List<byte[]> storeData(List<byte[]> blocks, int P1) throws CardException, GPException {
        List<byte[]> result = new ArrayList<>();
        for (int i = 0; i < blocks.size(); i++) {
            CommandAPDU store = new CommandAPDU(CLA_GP, INS_STORE_DATA, (i == (blocks.size() - 1)) ? P1 | 0x80 : P1 & 0x7F, i, blocks.get(i), 256);
            result.add(GPException.check(transmit(store), "STORE DATA failed").getData());
        }
        return result;
    }

    byte[] _storeDataSingle(byte[] data, int P1, int P2) throws CardException, GPException {
        CommandAPDU store = new CommandAPDU(CLA_GP, INS_STORE_DATA, P1, P2, data, 256);
        return GPException.check(transmit(store), "STORE DATA failed").getData();
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
        ResponseAPDU response = transmitLV(install);
        GPException.check(response, "INSTALL [for make selectable] failed");
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

    public void putKeys(List<GPKey> keys, boolean replace) throws GPException, CardException {
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
//            // TODO: move to GPTool
//            if ((tmpl.get(0).getVersion() < 1 || tmpl.get(0).getVersion() > 0x7F) && replace) {
//                giveStrictWarning("Trying to replace factory keys, when you need to add new ones? Is this a virgin card? (use --virgin)");
//            }
//
//            // Check if key types and lengths are the same when replacing
//            if (replace && (keys.get(0).getType() != tmpl.get(0).getType() || keys.get(0).getLength() != tmpl.get(0).getLength())) {
//                // FIXME: SCE60 template has 3DES keys but uses AES.
//                giveStrictWarning("Can not replace keys of different type or size: " + tmpl.get(0).getType() + "->" + keys.get(0).getType());
//            }
//
//            // Check for matching version numbers if replacing and vice versa
//            if (!replace && (keys.get(0).getVersion() == tmpl.get(0).getVersion())) {
//                throw new IllegalArgumentException("Not adding keys and version matches existing?");
//            }
//
//            if (replace && (keys.get(0).getVersion() != tmpl.get(0).getVersion())) {
//                throw new IllegalArgumentException("Replacing keys and versions don't match existing?");
//            }
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
            for (GPKey k : keys) {
                bo.write(encodeKey(k, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.DEK), true));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        CommandAPDU command = new CommandAPDU(CLA_GP, INS_PUT_KEY, P1, P2, bo.toByteArray());
        ResponseAPDU response = transmit(command);
        GPException.check(response, "PUT KEY failed");
    }

    // Puts a RSA public key for DAP purposes (format 1)
    public void putKey(RSAPublicKey pubkey, int version) throws CardException, GPException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();

        try {
            bo.write(version); // DAP key Version number
            bo.write(0xA1); // Modulus
            byte[] modulus = GPUtils.positive(pubkey.getModulus());
            byte[] exponent = GPUtils.positive(pubkey.getPublicExponent());
            bo.write(modulus.length);
            bo.write(modulus);
            bo.write(0xA0);
            bo.write(exponent.length);
            bo.write(exponent);
            bo.write(0x00); // No KCV
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        CommandAPDU command = new CommandAPDU(CLA_GP, INS_PUT_KEY, 0x00, 0x01, bo.toByteArray());
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

}
