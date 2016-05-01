/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 * Copyright (C) 2014-2016 Martin Paljak, martin@martinpaljak.net
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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;

import apdu4j.HexUtils;
import apdu4j.ISO7816;
import pro.javacard.gp.GPData.KeyType;
import pro.javacard.gp.GPKeySet.Diversification;
import pro.javacard.gp.GPKeySet.GPKey;
import pro.javacard.gp.GPKeySet.GPKey.Type;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privileges;

/**
 * The main Global Platform class. Provides most of the Global Platform
 * functionality for managing GP compliant smart cards.
 */
public class GlobalPlatform {
	// Not static because of the overall statefulness of the class
	// Also allows to have the "-v" in the gp tool
	private static Logger logger = LoggerFactory.getLogger(GlobalPlatform.class);

	public static final short SHORT_0 = 0;
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

	public enum APDUMode {
		// bit values as expected by EXTERNAL AUTHENTICATE
		CLR(0x00), MAC(0x01), ENC(0x02), RMAC(0x10);

		private final int value;
		private APDUMode(int value) {this.value = value;}

		public static int getSetValue(EnumSet<APDUMode> s) {
			int v = 0;
			for (APDUMode m : s) {
				v |= m.value;
			}
			return v;
		}
	};

	public static EnumSet<APDUMode> defaultMode = EnumSet.of(APDUMode.MAC);

	// Implementation details
	private static final byte CLA_GP = (byte) 0x80;
	private static final byte CLA_MAC = (byte) 0x84;
	private static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
	private static final byte INS_INSTALL = (byte) 0xE6;
	private static final byte INS_LOAD = (byte) 0xE8;
	private static final byte INS_DELETE = (byte) 0xE4;
	private static final byte INS_GET_STATUS = (byte) 0xF2;
	private static final byte INS_SET_STATUS = (byte) 0xF0;
	private static final byte INS_PUT_KEY = (byte) 0xD8;
	private static final byte INS_STORE_DATA = (byte) 0xE2;
	private static final byte INS_GET_DATA = (byte) 0xCA;

	// SD AID of the card successfully selected or null
	public AID sdAID = null;
	public static enum GPSpec {OP201, GP211, GP22};
	GPSpec spec = GPSpec.GP211;

	// Either 1 or 2 or 3
	private int scpMajorVersion = 0;

	private int blockSize = 255;
	private GPKeySet sessionKeys;
	private SCPWrapper wrapper = null;
	private CardChannel channel = null;
	private byte[] diversification_data = null;

	private byte[] cplc = null;
	private GPRegistry registry = null;
	private boolean dirty = true; // True if registry is dirty.

	protected boolean strict = true;


	/**
	 * Start a GlobalPlatform session to a card
	 *
	 * Maintaining locks to the underlying hardware is the duty of the caller
	 *
	 * @param channel channel to talk to
	 * @throws IllegalArgumentException if {@code channel} is null.
	 */
	public GlobalPlatform(CardChannel channel) {
		if (channel == null) {
			throw new IllegalArgumentException("A card session is required");
		}
		this.channel = channel;
	}

	public CardChannel getChannel() {
		return channel;
	}
	/**
	 * Get the version and build information of the library.
	 * @return
	 */
	public static String getVersion() {
		try (InputStream versionfile = GlobalPlatform.class.getResourceAsStream("version.txt")) {
			String version = "unknown-development";
			if (versionfile != null) {
				try (BufferedReader vinfo = new BufferedReader(new InputStreamReader(versionfile)) ) {
					version = vinfo.readLine();
				}
			}
			return version;
		} catch (IOException e) {
			return "unknown-error";
		}
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

	@Deprecated
	public void imFeelingLucky() throws CardException, GPException {
		select(null); // auto-detect ISD AID
		SessionKeyProvider keys = PlaintextKeys.fromMasterKey(GPData.defaultKey, Diversification.NONE);
		openSecureChannel(keys, null, 0, EnumSet.of(APDUMode.MAC));
	}

	protected void giveStrictWarning(String message) throws GPException {
		message = "STRICT WARNING: "+ message;
		if (strict) {
			throw new GPException(message);
		} else {
			logger.warn(message);
		}
	}

	public boolean select(AID sdAID) throws GPException, CardException {
		// Try to select ISD without giving the sdAID
		final CommandAPDU command;
		if (sdAID == null ) {
			command = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 0x04, 0x00, 256);
		} else {
			command = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 0x04, 0x00, sdAID.getBytes(), 256);
		}
		ResponseAPDU resp = channel.transmit(command);

		// Unfused JCOP replies with 0x6A82 to everything
		if (sdAID == null && resp.getSW() == 0x6A82) {
			// If it has the identification AID, it probably is an unfused JCOP
			byte [] identify_aid = HexUtils.hex2bin("A000000167413000FF");
			CommandAPDU identify = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 0x04, 0x00, identify_aid, 256);
			ResponseAPDU identify_resp = channel.transmit(identify);
			byte[] identify_data = identify_resp.getData();
			// Check the fuse state
			if (identify_data.length > 15) {
				if (identify_data[14] == 0x00) {
					giveStrictWarning("Unfused JCOP detected");
				}
			}
		}
		// If the ISD is locked, log it.
		if (resp.getSW() == 0x6283) {
			logger.warn("SELECT ISD returned 6283 - CARD_LOCKED");
		}

		if (resp.getSW() == 0x9000 || resp.getSW() == 0x6283) {
			// The security domain AID is in FCI.
			byte[] fci = resp.getData();
			parse_select_response(fci);
			return true;
		}
		return false;
	}


	private void parse_select_response(byte [] fci) throws GPException {
		try (ASN1InputStream ais = new ASN1InputStream(fci)) {
			if (ais.available() > 0) {
				// Read FCI
				DERApplicationSpecific fcidata = (DERApplicationSpecific) ais.readObject();
				// FIXME System.out.println(ASN1Dump.dumpAsString(fcidata, true));
				if (fcidata.getApplicationTag() == 15) {
					ASN1Sequence s = ASN1Sequence.getInstance(fcidata.getObject(BERTags.SEQUENCE));
					for (ASN1Encodable e: Lists.newArrayList(s.iterator())) {
						ASN1TaggedObject t = DERTaggedObject.getInstance(e);
						if (t.getTagNo() == 4) {
							// ISD AID
							ASN1OctetString isdaid = DEROctetString.getInstance(t.getObject());
							AID detectedAID = new AID(isdaid.getOctets());
							if (sdAID == null) {
								logger.debug("Auto-detected ISD AID: " + detectedAID);
							}
							if (sdAID != null && !detectedAID.equals(sdAID)) {
								giveStrictWarning("SD AID in FCI does not match the requested AID!");
							}
							this.sdAID = sdAID == null ? detectedAID : sdAID;
						} else if (t.getTagNo() == 5) {
							// Proprietary, usually a sequence
							if (t.getObject() instanceof ASN1Sequence) {
								ASN1Sequence prop = ASN1Sequence.getInstance(t.getObject());
								for (ASN1Encodable enc: Lists.newArrayList(prop.iterator())) {
									ASN1Primitive proptag = enc.toASN1Primitive();
									if (proptag instanceof DERApplicationSpecific) {
										DERApplicationSpecific isddata = (DERApplicationSpecific) proptag;
										if (isddata.getApplicationTag() == 19) {
											spec = GPData.get_version_from_card_data(isddata.getEncoded());
											logger.debug("Auto-detected GP version: " + spec);
										}
									} else if (proptag instanceof DERTaggedObject) {
										DERTaggedObject tag = (DERTaggedObject)proptag;
										if (tag.getTagNo() == 101) {
											setBlockSize(DEROctetString.getInstance(tag.getObject()));
										} else if (tag.getTagNo() == 110) {
											logger.debug("Lifecycle data (ignored): " + HexUtils.bin2hex(tag.getObject().getEncoded()));
										} else {
											logger.info("Unknown/unhandled tag in FCI proprietary data: " + HexUtils.bin2hex(tag.getEncoded()));
										}
									} else {
										throw new GPException("Unknown data from card: " + HexUtils.bin2hex(proptag.getEncoded()));
									}
								}
							} else {
								// Except Feitian cards which have a plain nested tag
								if (t.getObject() instanceof DERTaggedObject) {
									DERTaggedObject tag = (DERTaggedObject)t.getObject();
									if (tag.getTagNo() == 101) {
										setBlockSize(DEROctetString.getInstance(tag.getObject()));
									} else {
										logger.info("Unknown/unhandled tag in FCI proprietary data: " + HexUtils.bin2hex(tag.getEncoded()));
									}
								}
							}
						} else {
							logger.info("Unknown/unhandled tag in FCI: " + HexUtils.bin2hex(t.getEncoded()));
						}
					}
				} else {
					throw new GPException("Unknown data from card: " + HexUtils.bin2hex(fci));
				}
			}
		} catch (IOException | ClassCastException e) {
			throw new GPException("Invalid data: " + e.getMessage(), e);
		}

	}

	private void setBlockSize(ASN1OctetString blocksize) {
		int bs = new BigInteger(1, blocksize.getOctets()).intValue();
		if (bs > this.blockSize) {
			logger.debug("Ignoring auto-detected block size that exceeds set maximum: " + bs);
		} else {
			this.blockSize = bs;
			logger.debug("Auto-detected block size: " + blockSize);
		}
	}

	/**
	 * Establish a connection to the security domain specified in the
	 * constructor or discovered. This method is required before doing
	 * {@link #openSecureChannel openSecureChannel}.
	 *
	 * @throws GPException
	 *             if security domain selection fails for some reason
	 * @throws CardException
	 *             on data transmission errors
	 */
	@Deprecated
	public void select() throws GPException, CardException {
		if (!select(null)) {
			throw new GPException("Could not select security domain!");
		}
	}

	private ResponseAPDU always_transmit(CommandAPDU cmd) throws CardException, GPException {
		if (wrapper != null) {
			return transmit(cmd);
		} else {
			return channel.transmit(cmd);
		}
	}

	public List<GPKeySet.GPKey> getKeyInfoTemplate() throws CardException, GPException {
		// FIXME: this assumes selected ISD. We always request the version with tags (GP CLA)
		// Key Information Template
		CommandAPDU command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0xE0, 256);
		ResponseAPDU resp = always_transmit(command);

		if (resp.getSW() == ISO7816.SW_NO_ERROR) {
			return GPData.get_key_template_list(resp.getData());
		} else {
			logger.warn("GET DATA(Key Information Template) not supported");
		}
		return GPData.get_key_template_list(null);
	}

	public byte[] fetchCardData() throws CardException, GPException {
		// Card data
		CommandAPDU command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0x66, 256);
		ResponseAPDU resp = always_transmit(command);
		if (resp.getSW() == 0x6A86) {
			logger.debug("GET DATA(CardData) not supported, Open Platform 2.0.1 card? " + GPUtils.swToString(resp.getSW()));
			return null;
		} else if (resp.getSW() == 0x9000) {
			return resp.getData();
		}
		return null;
	}

	public void dumpCardProperties(PrintStream out) throws CardException, GPException {

		// Key Information Template
		List<GPKey> key_templates = getKeyInfoTemplate();
		if (key_templates != null && key_templates.size() > 0) {
			GPData.pretty_print_key_template(key_templates, out);
		}

		out.println("***** GET DATA:");

		// Issuer Identification Number (IIN)
		CommandAPDU command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0x42, 256);
		ResponseAPDU resp = channel.transmit(command);
		if (resp.getSW() == 0x9000) {
			out.println("IIN " + HexUtils.bin2hex(resp.getData()));
		} else {
			out.println("GET DATA(IIN) not supported");
		}

		// Card Image Number (CIN)
		command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0x45, 256);
		resp = channel.transmit(command);
		if (resp.getSW() == 0x9000) {
			out.println("CIN " + HexUtils.bin2hex(resp.getData()));
		} else {
			out.println("GET DATA(CIN) not supported");
		}

		// Sequence Counter of the default Key Version Number (tag 0xC1)
		command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0xC1, 256);
		resp = channel.transmit(command);
		if (resp.getSW() == 0x9000) {
			byte [] ssc = resp.getData();
			out.println("SSC " + HexUtils.bin2hex(TLVUtils.getTLVValueAsBytes(ssc, SHORT_0)));
		} else {
			out.println("GET DATA(SSC) not supported");
		}
		out.println("*****");
	}

	public byte[] fetchCPLC() throws CardException, GPException {
		CommandAPDU command = new CommandAPDU(CLA_GP, INS_GET_DATA, 0x9F, 0x7F, 256);
		ResponseAPDU resp = channel.transmit(command);

		if (resp.getSW() == ISO7816.SW_NO_ERROR) {
			return resp.getData();
		} else {
			logger.debug("GET DATA(CPLC) returned SW: " + GPUtils.swToString(resp.getSW()));
		}
		return null;
	}

	public byte[] getCPLC() throws CardException, GPException {
		if (cplc == null)
			cplc = fetchCPLC();
		return cplc;
	}

	public byte [] getDiversificationData() {
		return diversification_data;
	}

	/**
	 * Establishes a secure channel to the security domain.
	 *
	 */
	public void openSecureChannel(SessionKeyProvider keys, byte[] host_challenge, int scpVersion, EnumSet<APDUMode> securityLevel)
			throws CardException, GPException {

		if (sdAID == null) {
			throw new IllegalStateException("No selected ISD!");
		}

		// ENC requires MAC
		if (securityLevel.contains(APDUMode.ENC)) {
			securityLevel.add(APDUMode.MAC);
		}

		// Generate host challenge
		if (host_challenge == null) {
			host_challenge = new byte[8];
			SecureRandom sr = new SecureRandom();
			sr.nextBytes(host_challenge);
		}

		// P1 key version (SCP1)
		// P2 either key ID (SCP01) or 0 (SCP2)
		// TODO: use it here for KeyID?
		CommandAPDU initUpdate = new CommandAPDU(CLA_GP, INS_INITIALIZE_UPDATE, keys.getKeysetVersion(), keys.getKeysetID(), host_challenge, 256);

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
		diversification_data = Arrays.copyOfRange(update_response, 0, 10);
		offset += diversification_data.length;
		// Get used key version from response
		int keyVersion = update_response[offset] & 0xFF;
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

		// FIXME: SCP02 has 2 byte sequence + 6 bytes card challenge but the challenge is discarded.
		// get card challenge
		byte card_challenge[] = Arrays.copyOfRange(update_response, offset, offset + 8);
		offset += card_challenge.length;
		// get card cryptogram
		byte card_cryptogram[] = Arrays.copyOfRange(update_response, offset, offset + 8);
		offset += card_cryptogram.length;

		logger.debug("Host challenge: " + HexUtils.bin2hex(host_challenge));
		logger.debug("Card challenge: " + HexUtils.bin2hex(card_challenge));

		// Verify response
		// If using explicit key version, it must match.
		if ((keys.getKeysetVersion() > 0) && (keyVersion != keys.getKeysetVersion())) {
			throw new GPException("Key version mismatch: " + keys.getKeysetVersion() + " != " + keyVersion);
		}

		logger.debug("Card reports SCP0" + scpMajorVersion + " with version " + keyVersion + " keys");

		// Set default SCP version based on major version, if not explicitly known.
		if (scpVersion == SCP_ANY) {
			if (scpMajorVersion == 1) {
				scpVersion = SCP_01_05;
			} else if (scpMajorVersion == 2) {
				scpVersion = SCP_02_15;
			} else if (scpMajorVersion == 3) {
				logger.debug("SCP03 i=" + scp_i);
				scpVersion = 3; // FIXME: the symbolic numbering of versions needs to be fixed.
			}
		} else if (scpVersion != scpMajorVersion) {
			logger.debug("Overriding SCP version: card reports " + scpMajorVersion + " but user requested " + scpVersion);
			scpMajorVersion = scpVersion;
			if (scpVersion == 1) {
				scpVersion = SCP_01_05;
			} else if (scpVersion == 2) {
				scpVersion = SCP_02_15;
			} else {
				logger.debug("error: " + scpVersion);
			}
		}

		// Remove RMAC if SCP01 TODO: this should be generic sanitizer somewhere
		if (scpMajorVersion == 1 && securityLevel.contains(APDUMode.RMAC)) {
			logger.debug("SCP01 does not support RMAC, removing.");
			securityLevel.remove(APDUMode.RMAC);
		}

		// Derive session keys
		byte [] seq = null;
		if (scpMajorVersion == 1) {
			sessionKeys = keys.getSessionKeys(scpMajorVersion, diversification_data, host_challenge, card_challenge);
		} else if (scpMajorVersion == 2) {
			seq = Arrays.copyOfRange(update_response, 12, 14);
			sessionKeys = keys.getSessionKeys(2, diversification_data, seq);
		} else if (scpMajorVersion == 3) {
			if (update_response.length == 32) {
				seq = Arrays.copyOfRange(update_response, 29, 32);
			}
			sessionKeys = keys.getSessionKeys(3, diversification_data, host_challenge, card_challenge);
		} else {
			throw new GPException("Don't know how to handle SCP version " + scpMajorVersion);
		}

		// Verify card cryptogram
		byte[] my_card_cryptogram = null;
		byte[] cntx = GPUtils.concatenate(host_challenge, card_challenge);
		if (scpMajorVersion == 1 || scpMajorVersion == 2) {
			my_card_cryptogram = GPCrypto.mac_3des_nulliv(sessionKeys.getKey(KeyType.ENC), cntx);
		} else {
			my_card_cryptogram = GPCrypto.scp03_kdf(sessionKeys.getKey(KeyType.MAC), (byte) 0x00, cntx, 64);
		}

		// This is the main check for possible successful authentication.
		if (!Arrays.equals(card_cryptogram, my_card_cryptogram)) {
			giveStrictWarning("Card cryptogram invalid!\nCard: " + HexUtils.bin2hex(card_cryptogram) + "\nHost: "+ HexUtils.bin2hex(my_card_cryptogram) + "\n!!! DO NOT RE-TRY THE SAME COMMAND/KEYS OR YOU MAY BRICK YOUR CARD !!!");
		} else {
			logger.debug("Verified card cryptogram: " + HexUtils.bin2hex(my_card_cryptogram));
		}

		// Calculate host cryptogram and initialize SCP wrapper
		byte[] host_cryptogram = null;
		if (scpMajorVersion == 1 || scpMajorVersion == 2) {
			host_cryptogram = GPCrypto.mac_3des_nulliv(sessionKeys.getKey(KeyType.ENC), GPUtils.concatenate(card_challenge, host_challenge));
			wrapper = new SCP0102Wrapper(sessionKeys, scpVersion, EnumSet.of(APDUMode.MAC), null, null, blockSize);
		} else {
			host_cryptogram = GPCrypto.scp03_kdf(sessionKeys.getKey(KeyType.MAC), (byte) 0x01, cntx, 64);
			wrapper = new SCP03Wrapper(sessionKeys, scpVersion, EnumSet.of(APDUMode.MAC), null, null, blockSize);
		}

		logger.debug("Calculated host cryptogram: " + HexUtils.bin2hex(host_cryptogram));
		int P1 = APDUMode.getSetValue(securityLevel);
		CommandAPDU externalAuthenticate = new CommandAPDU(CLA_MAC, ISO7816.INS_EXTERNAL_AUTHENTICATE_82, P1, 0, host_cryptogram);
		response = transmit(externalAuthenticate);
		GPException.check(response, "External authenticate failed");
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

	public void loadCapFile(CapFile cap) throws CardException, GPException{
		loadCapFile(cap, false, false, false, false);
	}

	private void loadCapFile(CapFile cap, boolean includeDebug, boolean separateComponents, boolean loadParam, boolean useHash)
			throws GPException, CardException {

		if (getRegistry().allAIDs().contains(cap.getPackageAID())) {
			giveStrictWarning("Package with AID " + cap.getPackageAID() + " is already present on card");
		}
		byte[] hash = useHash ? cap.getLoadFileDataHash("SHA1", includeDebug) : new byte[0];
		int len = cap.getCodeLength(includeDebug);
		// FIXME: parameters are optional for load
		byte[] loadParams = loadParam ? new byte[] { (byte) 0xEF, 0x04, (byte) 0xC6, 0x02, (byte) ((len & 0xFF00) >> 8),
				(byte) (len & 0xFF) } : new byte[0];

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
	 * <P>
	 * Before installation the package containing the applet must be loaded onto
	 * the card, see {@link #loadCapFile loadCapFile}.
	 * <P>
	 * This method installs just one applet. Call it several times for packages
	 * containing several applets.
	 *
	 * @param packageAID
	 *            the package that containing the applet
	 * @param appletAID
	 *            the applet to be installed
	 * @param instanceAID
	 *            the applet AID passed to the install method of the applet,
	 *            defaults to {@code packageAID} if null
	 * @param privileges
	 *            privileges encoded as byte
	 * @param installParams
	 *            tagged installation parameters, defaults to {@code 0xC9 00}
	 *            (ie. no installation parameters) if null, if non-null the
	 *            format is {@code 0xC9 len data...}
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
			installParams = new byte[] { (byte) 0xC9, 0x00 };
		}
		if (installToken == null) {
			installToken = new byte[0];
		}
		byte [] privs = privileges.toBytes();
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
	 *
	 * @throws GPException
	 * @throws CardException
	 *
	 * @see GP 2.1.1 9.5.2
	 *
	 */
	public void storeData(AID aid, byte []data) throws CardException, GPException {
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
		}
		catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}
		CommandAPDU install = new CommandAPDU(CLA_GP, INS_INSTALL, 0x20, 0x00, bo.toByteArray());
		ResponseAPDU response = transmit(install);
		GPException.check(response, "Install for personalization failed");

		// Now pump the data
		List<byte[]> blocks = GPUtils.splitArray(data, wrapper.getBlockSize());
		for (int i = 0; i < blocks.size(); i++) {
			CommandAPDU load = new CommandAPDU(CLA_GP, INS_STORE_DATA, (i == (blocks.size() - 1)) ? 0x80 : 0x00, (byte) i, blocks.get(i));
			response = transmit(load);
			GPException.check(response, "STORE DATA failed");
		}
	}

	public void makeDefaultSelected(AID aid) throws CardException, GPException {
		// FIXME: only works for some 2.1.1 cards ?
		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		// Only supported privilege.
		byte privileges = GPData.defaultSelectedPriv;
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
		CommandAPDU cmd = new CommandAPDU(CLA_GP, INS_SET_STATUS, 0x80, status);
		ResponseAPDU response = transmit(cmd);
		GPException.check(response, "SET STATUS failed");
		dirty = true;
	}

	/**
	 * Delete file {@code aid} on the card. Delete dependencies as well if
	 * {@code deleteDeps} is true.
	 *
	 * @param aid
	 *            identifier of the file to delete
	 * @param deleteDeps
	 *            if true delete dependencies as well
	 * @throws CardException
	 *             for low-level communication errors
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

	// FIXME: remove the withCheck parameter, as always true?
	private byte[] encodeKey(GPKey key, GPKey kek, boolean withCheck) {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			if (key.getType()== Type.DES3) {
				baos.write(0x80); // 3DES
				// Length
				baos.write(16);
				// Encrypt key with KEK
				Cipher cipher;
				cipher = Cipher.getInstance("DESede/ECB/NoPadding");
				cipher.init(Cipher.ENCRYPT_MODE, kek.getKey());
				baos.write(cipher.doFinal(key.getValue(), 0, 16));
				if (withCheck) {
					byte[] kcv = GPCrypto.kcv_3des(key);
					baos.write(kcv.length);
					baos.write(kcv);
				} else {
					baos.write(0);
				}
			} else if (key.getType() == Type.AES) {
				//	baos.write(0xFF);
				baos.write(0x88); // AES
				baos.write(0x11); // 128b keys only currently
				byte [] cgram = GPCrypto.scp03_encrypt_key(kek, key);
				baos.write(cgram.length);
				baos.write(cgram);
				byte [] check = GPCrypto.scp03_key_check_value(key);
				baos.write(check.length);
				baos.write(check);
			} else {
				throw new RuntimeException("Don't know how to handle " + key.getType());
			}
			return baos.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException(e);
		} catch (BadPaddingException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException(e);
		}
	}


	public void putKeys(List<GPKeySet.GPKey> keys, boolean replace) throws GPException, CardException {
		if (keys.size() < 1 || keys.size() > 3) {
			throw new IllegalArgumentException("Can add 1 or up to 3 keys at a time");
		}

		// Debug
		logger.debug("Replace: " + replace);
		for (GPKey k: keys) {
			logger.debug("PUT KEY:" + k);
		}

		// Check for sanity.
		if (keys.size() > 1) {
			for (int i = 1; i < keys.size(); i++) {
				if (keys.get(i-1).getID() != keys.get(i).getID() -1) {
					throw new IllegalArgumentException("Key ID-s of multiple keys must be sequential!");
				}
			}
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
				logger.debug("No key template on card but trying to replace. Implying add");
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
			for (GPKey k: keys) {
				bo.write(encodeKey(k, sessionKeys.getKey(KeyType.KEK), true));
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		CommandAPDU command = new CommandAPDU(CLA_GP, INS_PUT_KEY, P1, P2, bo.toByteArray());
		ResponseAPDU response = transmit(command);
		GPException.check(response,"PUT KEY failed");
	}


	public GPRegistry getRegistry() throws GPException, CardException{
		if (dirty) {
			registry = getStatus();
			dirty = false;
		}
		return registry;
	}


	// TODO: The way registry parsing mode is piggybacked to the registry class is not really nice.
	private byte[] getConcatenatedStatus(GPRegistry reg, int p1, byte[] data) throws CardException, GPException {
		// By default use tags
		int p2 = reg.tags? 0x02 : 0x00;

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
			logger.warn("GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()) + " with " + Integer.toHexString(sw));
			return response.getData();
		}

		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		try {
			bo.write(response.getData());

			while (response.getSW() == 0x6310) {
				cmd = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, p2 | 0x01, data, 256);
				response = transmit(cmd);

				sw = response.getSW();
				if ((sw != ISO7816.SW_NO_ERROR) && (sw != 0x6310)) {
					throw new GPException(sw, "GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()));
				}
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
		byte[] data = getConcatenatedStatus(registry, 0x80, new byte[] { 0x4F, 0x00 });
		registry.parse(0x80, data, Kind.IssuerSecurityDomain, spec);

		// Apps and security domains
		data = getConcatenatedStatus(registry, 0x40, new byte[] { 0x4F, 0x00 });
		registry.parse(0x40, data, Kind.Application, spec);

		// Load files
		data = getConcatenatedStatus(registry, 0x20, new byte[] { 0x4F, 0x00 });
		registry.parse(0x20, data, Kind.ExecutableLoadFile, spec);

		if (spec != GPSpec.OP201) { // TODO: remove
			// Load files with modules
			data = getConcatenatedStatus(registry, 0x10, new byte[] { 0x4F, 0x00 });
			registry.parse(0x10, data, Kind.ExecutableLoadFile, spec);
		}
		return registry;
	}

	public static class SCP0102Wrapper extends SCPWrapper {

		private byte[] icv = null;
		private byte[] ricv = null;
		private int scp = 0;

		private final ByteArrayOutputStream rMac = new ByteArrayOutputStream();

		private boolean icvEnc = false;

		private boolean preAPDU = false;
		private boolean postAPDU = false;



		private SCP0102Wrapper(GPKeySet sessionKeys, int scp, EnumSet<APDUMode> securityLevel, byte[] icv, byte[] ricv, int bs) {
			this.blockSize = bs;
			this.sessionKeys = sessionKeys;
			this.icv = icv;
			this.ricv = ricv;
			setSCPVersion(scp);
			setSecurityLevel(securityLevel);
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

		private static byte clearBits(byte b, byte mask) {
			return (byte) ((b & ~mask) & 0xFF);
		}

		private static byte setBits(byte b, byte mask) {
			return (byte) ((b | mask) & 0xFF);
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
							c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(KeyType.MAC));
						} else {
							c = Cipher.getInstance(GPCrypto.DES_ECB_CIPHER);
							c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKey(KeyType.MAC).getKey(Type.DES));
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
						icv = GPCrypto.mac_3des(sessionKeys.getKey(KeyType.MAC), t.toByteArray(), icv);
					} else if (scp == 2) {
						icv = GPCrypto.mac_des_3des(sessionKeys.getKey(KeyType.MAC), t.toByteArray(), icv);
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
					c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(KeyType.ENC), GPCrypto.iv_null_des);
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
			} catch (InvalidKeyException | InvalidAlgorithmParameterException |IllegalBlockSizeException | BadPaddingException e) {
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

				ricv = GPCrypto.mac_des_3des(sessionKeys.getKey(KeyType.RMAC), GPCrypto.pad80(rMac.toByteArray(), 8), ricv);

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

	public static class SCP03Wrapper extends SCPWrapper {
		// Both are block size length
		byte [] chaining_value = new byte[16];
		byte [] encryption_counter = new byte[16];

		private SCP03Wrapper(GPKeySet sessionKeys, int scp, EnumSet<APDUMode> securityLevel, byte[] icv, byte[] ricv, int bs) {
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
			byte [] cmd_mac = null;

			try {
				int cla = command.getCLA();
				int lc = command.getNc();
				byte [] data = command.getData();

				// Encrypt if needed
				if (enc) {
					cla = 0x84;
					// Counter shall always be incremented
					GPCrypto.buffer_increment(encryption_counter);
					if (command.getData().length > 0) {
						byte [] d = GPCrypto.pad80(command.getData(), 16);
						// Encrypt with S-ENC, after increasing the counter
						Cipher c = Cipher.getInstance(GPCrypto.AES_CBC_CIPHER);
						c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(KeyType.ENC), GPCrypto.iv_null_aes);
						byte [] iv = c.doFinal(encryption_counter);
						// Now encrypt the data with S-ENC.
						c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(KeyType.ENC), new IvParameterSpec(iv));
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
					byte [] cmac_input = bo.toByteArray();
					byte [] cmac = GPCrypto.scp03_mac(sessionKeys.getKey(KeyType.MAC), cmac_input, 128);
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
				byte [] new_apdu = na.toByteArray();
				return new CommandAPDU(new_apdu);
			}  catch (IOException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new IllegalStateException("APDU wrapping failed", e);
			} catch (InvalidKeyException | InvalidAlgorithmParameterException |IllegalBlockSizeException | BadPaddingException e) {
				throw new GPException("APDU wrapping failed", e);
			}
		}

		@Override
		protected ResponseAPDU unwrap(ResponseAPDU response) throws GPException {
			return response;
		}
	}

	public static abstract class SCPWrapper {
		protected int blockSize = 0;
		protected GPKeySet sessionKeys = null;
		protected boolean mac = false;
		protected boolean enc = false;
		protected boolean rmac = false;

		public void setSecurityLevel(EnumSet<APDUMode> securityLevel) {
			mac = securityLevel.contains(APDUMode.MAC);
			enc = securityLevel.contains(APDUMode.ENC);
			rmac = securityLevel.contains(APDUMode.RMAC);
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
