/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 * Copyright (C) 2014 Martin Paljak, martin@martinpaljak.net
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

package openkms.gp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
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

import openkms.gp.GPData.KeyType;
import openkms.gp.GPKeySet.Diversification;
import openkms.gp.GPKeySet.GPKey;
import openkms.gp.GPKeySet.GPKey.Type;
import apdu4j.HexUtils;
import apdu4j.ISO7816;

/**
 * The main Global Platform class. Provides most of the Global Platform
 * functionality for managing GP compliant smart cards.
 */
public class GlobalPlatform {
	public static final String sdk_version = "v0.2";
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
	public EnumSet<APDUMode> defaultMode = EnumSet.of(APDUMode.MAC);

	// Implementation details
	private static final byte CLA_GP = (byte) 0x80;
	private static final byte CLA_MAC = (byte) 0x84;
	private static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
	private static final byte INS_INSTALL = (byte) 0xE6;
	private static final byte INS_LOAD = (byte) 0xE8;
	private static final byte INS_DELETE = (byte) 0xE4;
	private static final byte INS_GET_STATUS = (byte) 0xF2;
	private static final byte INS_PUT_KEY = (byte) 0xD8;


	// AID of the card successfully selected or null
	public AID sdAID = null;

	// Either 1 or 2 or 3
	private int scpMajorVersion = 0;

	public static final int defaultLoadSize = 255; // TODO: Check CardData
	private SCPWrapper wrapper = null;
	private GPKeySet staticKeys = null;
	private CardChannel channel = null;

	private byte[] cplc = null;
	private AIDRegistry registry = null;
	private boolean dirty = true; // True if registry is dirty.
	private PrintStream verboseTo = null;
	protected boolean strict = true;


	/**
	 * Set the channel and use the default security domain AID and scpAny.
	 *
	 * @param channel
	 *            channel to talk to
	 * @throws IllegalArgumentException
	 *             if {@code channel} is null.
	 */
	public GlobalPlatform(CardChannel channel) {
		this.channel = channel;
	}

	protected boolean beVerbose() {
		return verboseTo != null;
	}
	public void beVerboseTo(PrintStream out) {
		this.verboseTo = new PrintStream(out, true);
	}
	protected void verbose(String s) {
		if (!beVerbose())
			return;
		verboseTo.println(s);
	}

	public void setStrict(boolean strict) {
		this.strict = strict;
	}

	public void imFeelingLucky() throws CardException, GPException {
		select(null); // auto-detect ISD AID
		Diversification div = GPData.suggestDiversification(getCPLC());
		GPKeySet ks = new GPKeySet(new GPKey(GPData.defaultKey, Type.DES3), div);
		openSecureChannel(ks, null, 0, EnumSet.of(APDUMode.MAC));
	}

	protected void printStrictWarning(String message) throws GPException {
		message = "STRICT WARNING: "+ message;
		if (strict) {
			throw new GPException(message);
		} else {
			System.err.println(message);
		}
	}
	// XXX: remove
	private int getGPCLA() {
		if (wrapper != null && wrapper.mac)
			return CLA_MAC;
		return CLA_GP;
	}
	public boolean select(AID sdAID) throws GPException, CardException {
		// Try to select ISD without giving the sdAID
		CommandAPDU command = null;
		if (sdAID == null )
			command = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 0x04, 0x00, 256);
		else
			command = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 0x04, 0x00, sdAID.getBytes(), 256);

		ResponseAPDU resp = channel.transmit(command);

		if (resp.getSW() == 0x6283) {
			printStrictWarning("SELECT ISD returned 6283 - CARD_LOCKED");
		}
		if (resp.getSW() == 0x9000 || resp.getSW() == 0x6283) {
			// The security domain AID is in FCI.
			byte[] fci = resp.getData();

			// Skip template information and find tag 0x84
			short aid_offset = TLVUtils.findTag(fci, TLVUtils.skipTagAndLength(fci, (short) 0, (byte) 0x6F), (byte) 0x84);
			int aid_length = TLVUtils.getTagLength(fci, aid_offset);

			AID detectedAID = new AID(fci, aid_offset + 2, aid_length);
			verbose("Auto-detected ISD AID: " + detectedAID);
			if (sdAID != null && !detectedAID.equals(sdAID)) {
				printStrictWarning("SD AID in FCI does not match the requested AID!");
			}
			this.sdAID = sdAID == null ? detectedAID : sdAID;
			return true;
			// TODO: parse the maximum command size as well and use with defaultLoadSize
		}
		return false;
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
	public void select() throws GPException, CardException, IOException {
		if (!select(null)) {
			throw new GPException("Could not select security domain!");
		}
	}


	public List<GPKeySet.GPKey> getKeyInfoTemplate() throws CardException, GPException {
		// Key Information Template
		CommandAPDU command = new CommandAPDU(getGPCLA(), ISO7816.INS_GET_DATA, 0x00, 0xE0, 256);
		ResponseAPDU resp = always_transmit(command);

		if (resp.getSW() == ISO7816.SW_CLA_NOT_SUPPORTED) {
			command = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_GET_DATA, 0x00, 0xE0, 256);
			resp = always_transmit(command);
		}
		if (resp.getSW() == ISO7816.SW_NO_ERROR) {
			return GPData.get_key_template_list(resp.getData(), SHORT_0);
		} else {
			verbose("GET DATA(Key Information Template) not supported");
		}
		return GPData.get_key_template_list(null, SHORT_0);
	}

	public byte[] fetchCardData() throws CardException, GPException {
		// Card data
		CommandAPDU command = new CommandAPDU(getGPCLA(), ISO7816.INS_GET_DATA, 0x00, 0x66, 256);
		ResponseAPDU resp = always_transmit(command);
		if (resp.getSW() == 0x6A86) {
			verbose("GET DATA(CardData) not supported, Open Platform 2.0.1 card? " + GPUtils.swToString(resp.getSW()));
			return null;
		} else if (resp.getSW() == 0x9000) {
			return resp.getData();
		}
		return null;
	}

	public void discoverCardProperties() throws CardException, GPException {

		// Key Information Template
		List<GPKey> key_templates = getKeyInfoTemplate();
		if (key_templates != null && key_templates.size() > 0) {
			GPData.pretty_print_key_template(key_templates, System.out);
		}

		System.out.println("***** GET DATA:");

		// Issuer Identification Number (IIN)
		CommandAPDU command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0x42, 256);
		ResponseAPDU resp = channel.transmit(command);
		if (resp.getSW() == 0x9000) {
			System.out.println("IIN " + HexUtils.encodeHexString(resp.getData()));
		} else {
			System.out.println("GET DATA(IIN) not supported");
		}

		// Card Image Number (CIN)
		command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0x45, 256);
		resp = channel.transmit(command);
		if (resp.getSW() == 0x9000) {
			System.out.println("CIN " + HexUtils.encodeHexString(resp.getData()));
		} else {
			System.out.println("GET DATA(CIN) not supported");
		}

		// Sequence Counter of the default Key Version Number
		command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0xC1, 256);
		resp = channel.transmit(command);
		if (resp.getSW() == 0x9000) {
			byte [] ssc = resp.getData();
			TLVUtils.expectTag(ssc, SHORT_0, (byte) 0xC1);
			System.out.println("SSC " + HexUtils.encodeHexString(TLVUtils.getTLVValueAsBytes(ssc, SHORT_0)));
		} else {
			System.out.println("GET DATA(SSC) not supported");
		}
		System.out.println("*****");
	}

	public byte[] fetchCPLC() throws CardException, GPException {
		CommandAPDU command = new CommandAPDU(getGPCLA(), ISO7816.INS_GET_DATA, 0x9F, 0x7F, 256);
		ResponseAPDU resp = always_transmit(command);
		// If GP CLA fails, try with ISO
		if (resp.getSW() == ISO7816.SW_CLA_NOT_SUPPORTED) {
			command = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_GET_DATA, 0x9F, 0x7F, 256);
			resp = always_transmit(command);
		}

		if (resp.getSW() == ISO7816.SW_NO_ERROR) {
			return resp.getData();
		} else {
			verbose("GET DATA(CPLC) returned SW: " + GPUtils.swToString(resp.getSW()));
		}
		return null;
	}

	public byte[] getCPLC() throws CardException, GPException {
		if (cplc == null)
			cplc = fetchCPLC();
		return cplc;
	}

	/**
	 * Establishes a secure channel to the security domain. The security domain
	 * must have been selected with {@link open open} before.
	 *
	 * @throws IllegalArgumentException
	 *             if the arguments are out of range or the keyset is undefined
	 * @throws CardException
	 *             if some communication problem is encountered.
	 */
	public void openSecureChannel(GPKeySet staticKeys, byte[] host_challenge, int scpVersion, EnumSet<APDUMode> securityLevel)
			throws CardException, GPException {

		if (sdAID == null) {
			throw new IllegalStateException("No selected ISD!");
		}

		this.staticKeys = staticKeys;
		GPKeySet sessionKeys = null;

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
		CommandAPDU initUpdate = new CommandAPDU(CLA_GP, INS_INITIALIZE_UPDATE, staticKeys.getKeyVersion(), staticKeys.getKeyID(), host_challenge);

		ResponseAPDU response = channel.transmit(initUpdate);
		int sw = response.getSW();

		// Detect and report locked cards in a more sensible way.
		if ((sw == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED) || (sw == ISO7816.SW_AUTHENTICATION_METHOD_BLOCKED)) {
			throw new GPException(sw, "INITIALIZE UPDATE failed, card LOCKED?");
		}

		// Detect all other errors
		check(response, "INITIALIZE UPDATE failed");
		byte[] update_response = response.getData();

		// Verify response length (SCP01/SCP02 + SCP03 + SCP03 w/ pseudorandom)
		if (update_response.length != 28 && update_response.length != 29 && update_response.length != 32) {
			throw new GPException("Invalid INITIALIZE UPDATE response length: " + update_response.length);
		}
		// Parse the response
		int offset = 0;
		byte diversification_data[] = Arrays.copyOfRange(update_response, 0, 10);
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

		verbose("Host challenge: " + HexUtils.encodeHexString(host_challenge));
		verbose("Card challenge: " + HexUtils.encodeHexString(card_challenge));

		// Verify response
		// If using explicit key version, it must match.
		if ((staticKeys.getKeyVersion() > 0) && (keyVersion != staticKeys.getKeyVersion())) {
			throw new GPException("Key version mismatch: " + staticKeys.getKeyVersion() + " != " + keyVersion);
		}

		verbose("Card reports SCP0" + scpMajorVersion + " with version " + keyVersion + " keys");
		verbose("Master keys: " + staticKeys);

		// Set default SCP version based on major version, if not explicitly known.
		if (scpVersion == SCP_ANY) {
			if (scpMajorVersion == 1) {
				scpVersion = SCP_01_05;
			} else if (scpMajorVersion == 2) {
				scpVersion = SCP_02_15;
			} else if (scpMajorVersion == 3) {
				verbose("SCP03 i=" + scp_i);
				scpVersion = 3; // FIXME: the symbolic numbering of versions needs to be gixed.
			}
		} else if (scpVersion != scpMajorVersion) {
			verbose("Overriding SCP version: card reports " + scpMajorVersion + " but user requested " + scpVersion);
			scpMajorVersion = scpVersion;
			if (scpVersion == 1) {
				scpVersion = SCP_01_05;
			} else if (scpVersion == 2) {
				scpVersion = SCP_02_15;
			} else {
				System.out.println("error: " + scpVersion);
			}
		}

		// Remove RMAC if SCP01 TODO: this should be generic sanitizer somewhere
		if (scpMajorVersion == 1 && securityLevel.contains(APDUMode.RMAC)) {
			verbose("SCP01 does not support RMAC, removing.");
			securityLevel.remove(APDUMode.RMAC);
		}

		// Response processed. Derive keys.

		// Only diversify default key sets that require it.
		// FIXME: keyset version does not matter here.
		if ((staticKeys.getKeyVersion() == 0) || (staticKeys.getKeyVersion() == 255)) {
			if (staticKeys.diversification != Diversification.NONE) {
				staticKeys.diversify(update_response, scpMajorVersion);
				verbose("Diversififed master keys: " + staticKeys);
			}
		}

		// Check that SCP03 would be using AES keys
		if (scpMajorVersion == 3) {
			for (GPKey k: staticKeys.getKeys().values()) {
				if (k.getType() != Type.AES) {
					printStrictWarning("Usign SCP03 but key set has 3DES keys?");
				}
			}
		}

		// Derive session keys
		byte [] seq = null;
		if (scpMajorVersion == 1) {
			sessionKeys = deriveSessionKeysSCP01(staticKeys, host_challenge, card_challenge);
		} else if (scpMajorVersion == 2) {
			seq = Arrays.copyOfRange(update_response, 12, 14);
			verbose("Sequnce counter: " + HexUtils.encodeHexString(seq));
			sessionKeys = deriveSessionKeysSCP02(staticKeys, seq, false);
		} else if (scpMajorVersion == 3) {
			if (update_response.length == 32) {
				seq = Arrays.copyOfRange(update_response, 29, 32);
			}
			sessionKeys = deriveSessionKeysSCP03(staticKeys, host_challenge, card_challenge);
		}
		verbose("Derived session keys: " + sessionKeys);

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
			printStrictWarning("Card cryptogram invalid!\nCard: " + HexUtils.encodeHexString(card_cryptogram) + "\nHost: "+ HexUtils.encodeHexString(my_card_cryptogram) + "\n!!! DO NOT RE-TRY THE SAME COMMAND/KEYS OR YOU MAY BRICK YOUR CARD !!!");
		} else {
			verbose("Verified card cryptogram: " + HexUtils.encodeHexString(my_card_cryptogram));
		}

		// Calculate host cryptogram and initialize SCP wrapper
		byte[] host_cryptogram = null;
		if (scpMajorVersion == 1 || scpMajorVersion == 2) {
			host_cryptogram = GPCrypto.mac_3des_nulliv(sessionKeys.getKey(KeyType.ENC), GPUtils.concatenate(card_challenge, host_challenge));
			wrapper = new SCP0102Wrapper(sessionKeys, scpVersion, EnumSet.of(APDUMode.MAC), null, null);
		} else {
			host_cryptogram = GPCrypto.scp03_kdf(sessionKeys.getKey(KeyType.MAC), (byte) 0x01, cntx, 64);
			wrapper = new SCP03Wrapper(sessionKeys, scpVersion, EnumSet.of(APDUMode.MAC), null, null);
		}

		verbose("Calculated host cryptogram: " + HexUtils.encodeHexString(host_cryptogram));
		int P1 = APDUMode.getSetValue(securityLevel);
		CommandAPDU externalAuthenticate = new CommandAPDU(CLA_MAC, ISO7816.INS_EXTERNAL_AUTHENTICATE_82, P1, 0, host_cryptogram);
		response = transmit(externalAuthenticate);
		check(response, "External authenticate failed");
		wrapper.setSecurityLevel(securityLevel);

		// FIXME: ugly stuff, ugly...
		if (scpMajorVersion != 3) {
			SCP0102Wrapper w = (SCP0102Wrapper) wrapper;
			if (securityLevel.contains(APDUMode.RMAC)) {
				w.setRMACIV(w.getIV());
			}
		}
	}

	private GPKeySet deriveSessionKeysSCP01(GPKeySet staticKeys, byte[] host_challenge, byte[] card_challenge) {
		GPKeySet sessionKeys = new GPKeySet();

		byte[] derivationData = new byte[16];
		System.arraycopy(card_challenge, 4, derivationData, 0, 4);
		System.arraycopy(host_challenge, 0, derivationData, 4, 4);
		System.arraycopy(card_challenge, 0, derivationData, 8, 4);
		System.arraycopy(host_challenge, 4, derivationData, 12, 4);

		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			for (KeyType v: KeyType.values()) {
				if (v == KeyType.RMAC) // skip RMAC key
					continue;
				cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(v));
				GPKey nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
				sessionKeys.setKey(v, nk);
			}
			// KEK is the same
			sessionKeys.setKey(KeyType.KEK, staticKeys.getKey(KeyType.KEK));
			return sessionKeys;
		} catch (BadPaddingException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		}
	}

	private GPKeySet deriveSessionKeysSCP02(GPKeySet staticKeys, byte[] sequence, boolean implicitChannel) {
		GPKeySet sessionKeys = new GPKeySet();

		try {
			Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");

			byte[] derivationData = new byte[16];
			System.arraycopy(sequence, 0, derivationData, 2, 2);

			byte[] constantMAC = new byte[] { (byte) 0x01, (byte) 0x01 };
			System.arraycopy(constantMAC, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(KeyType.MAC), GPCrypto.iv_null_des);
			GPKey nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
			sessionKeys.setKey(KeyType.MAC, nk);

			// TODO: is this correct? - increment by one for all other than C-MAC
			if (implicitChannel) {
				TLVUtils.buffer_increment(derivationData, (short)2, (short)2);
			}

			byte[] constantRMAC = new byte[] { (byte) 0x01, (byte) 0x02 };
			System.arraycopy(constantRMAC, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(KeyType.MAC), GPCrypto.iv_null_des);
			nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
			sessionKeys.setKey(KeyType.RMAC, nk);


			byte[] constantENC = new byte[] { (byte) 0x01, (byte) 0x82 };
			System.arraycopy(constantENC, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(KeyType.ENC), GPCrypto.iv_null_des);
			nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
			sessionKeys.setKey(KeyType.ENC, nk);

			byte[] constantDEK = new byte[] { (byte) 0x01, (byte) 0x81 };
			System.arraycopy(constantDEK, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(KeyType.KEK), GPCrypto.iv_null_des);
			nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
			sessionKeys.setKey(KeyType.KEK, nk);
			return sessionKeys;

		} catch (BadPaddingException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		}
	}

	private GPKeySet deriveSessionKeysSCP03(GPKeySet staticKeys, byte[] host_challenge, byte[] card_challenge) {
		GPKeySet sessionKeys = new GPKeySet();
		final byte mac_constant = 0x06;
		final byte enc_constant = 0x04;
		final byte rmac_constant = 0x07;

		byte []context = GPUtils.concatenate(host_challenge, card_challenge);

		// MAC
		byte []kdf = GPCrypto.scp03_kdf(staticKeys.getKey(KeyType.MAC), mac_constant, context, 128);
		sessionKeys.setKey(KeyType.MAC, new GPKey(kdf, Type.AES));
		// ENC
		kdf = GPCrypto.scp03_kdf(staticKeys.getKey(KeyType.ENC), enc_constant, context, 128);
		sessionKeys.setKey(KeyType.ENC, new GPKey(kdf, Type.AES));
		// RMAC
		kdf = GPCrypto.scp03_kdf(staticKeys.getKey(KeyType.MAC), rmac_constant, context, 128);
		sessionKeys.setKey(KeyType.RMAC, new GPKey(kdf, Type.AES));

		// KEK remains the same
		sessionKeys.setKey(KeyType.KEK, staticKeys.getKey(KeyType.KEK));
		return sessionKeys;
	}


	public ResponseAPDU transmit(CommandAPDU command) throws CardException, GPException {
		CommandAPDU wc = wrapper.wrap(command);
		ResponseAPDU wr = channel.transmit(wc);
		return wrapper.unwrap(wr);
	}

	private ResponseAPDU always_transmit(CommandAPDU command) throws CardException, GPException {
		if (wrapper == null)
			return channel.transmit(command);
		else
			return transmit(command);
	}


	public AIDRegistry getRegistry() throws GPException, CardException{
		if (dirty) {
			registry = getStatus();
			dirty = false;
		}
		return registry;
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
			printStrictWarning("Package with AID " + cap.getPackageAID() + " is already present on card");
		}
		byte[] hash = useHash ? cap.getLoadFileDataHash(includeDebug) : new byte[0];
		int len = cap.getCodeLength(includeDebug);
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
		check(response, "Install for Load failed");

		List<byte[]> blocks = cap.getLoadBlocks(includeDebug, separateComponents, wrapper.getBlockSize());
		for (int i = 0; i < blocks.size(); i++) {
			CommandAPDU load = new CommandAPDU(CLA_GP, INS_LOAD, (i == (blocks.size() - 1)) ? 0x80 : 0x00, (byte) i, blocks.get(i));
			response = transmit(load);
			check(response, "LOAD failed");
		}
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
	public void installAndMakeSelectable(AID packageAID, AID appletAID, AID instanceAID, byte privileges, byte[] installParams,
			byte[] installToken) throws GPException, CardException {

		if (instanceAID == null) {
			instanceAID = appletAID;
		}
		if (getRegistry().allAppletAIDs().contains(instanceAID)) {
			printStrictWarning("Applet with instance AID " + instanceAID + " is already present on card");
		}
		if (installParams == null) {
			installParams = new byte[] { (byte) 0xC9, 0x00 };
		}
		if (installToken == null) {
			installToken = new byte[0];
		}
		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		try {
			bo.write(packageAID.getLength());
			bo.write(packageAID.getBytes());

			bo.write(appletAID.getLength());
			bo.write(appletAID.getBytes());

			bo.write(instanceAID.getLength());
			bo.write(instanceAID.getBytes());

			bo.write(1);
			bo.write(privileges);

			bo.write(installParams.length);
			bo.write(installParams);

			bo.write(installToken.length);
			bo.write(installToken);
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}

		CommandAPDU install = new CommandAPDU(CLA_GP, INS_INSTALL, 0x0C, 0x00, bo.toByteArray());
		ResponseAPDU response = transmit(install);
		check(response, "Install for Install and make selectable failed");
		dirty = true;
	}


	public void makeDefaultSelected(AID aid, byte privileges) throws CardException, GPException {
		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		// Only supported privilege.
		privileges = 0x04;
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
		check(response, "Install for make selectable failed");
		dirty = true;
	}

	public void uninstallDefaultSelected(boolean deps) throws CardException, GPException {
		AID def = getRegistry().getDefaultSelectedAID();
		if (def != null) {
			deleteAID(def, deps); // Can not work, need to locate the executable module
		} else {
			verbose("No default selected applet!");
		}
	}



	/**
	 * Delete file {@code aid} on the card. Delete dependencies as well if
	 * {@code deleteDeps} is true.
	 *
	 * @param aid
	 *            identifier of the file to delete
	 * @param deleteDeps
	 *            if true delete dependencies as well
	 * @throws GPDelete
	 *             if the delete command fails with a non 9000 response status
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
		check(response, "Deletion failed");
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
					// key check value, 3 bytes with new key over 8 null bytes
					baos.write(3);
					cipher.init(Cipher.ENCRYPT_MODE, key.getKey());
					byte check[] = cipher.doFinal(GPCrypto.null_bytes_8);
					baos.write(check, 0, 3);
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
		verbose("Replace: " + replace);
		for (GPKey k: keys) {
			verbose("PUT KEY:" + k);
		}

		// Check for sainity.
		if (keys.size() > 1) {
			for (int i = 1; i < keys.size(); i++) {
				if (keys.get(i-1).getID() != keys.get(i).getID() -1) {
					throw new IllegalArgumentException("Key ID-s of multiple keys must be sequential!");
				}
			}
		}

		// Check if factory keys
		List<GPKey> tmpl = getKeyInfoTemplate();
		if ((tmpl.get(0).getVersion() < 1 || tmpl.get(0).getVersion() > 0x7F) && replace) {
			printStrictWarning("Trying to replace factory keys, when you need to add new ones? Is this a virgin card? (use --virgin)");
		}

		// Check if key types and lengths are the same when replacing
		if (replace && (keys.get(0).getType() != tmpl.get(0).getType() || keys.get(0).getLength() != tmpl.get(0).getLength())) {
			throw new IllegalArgumentException("Can not replace keys of different type or size.");
		}

		// Check for matching version numbers if replacing and vice versa
		if (!replace && (keys.get(0).getVersion() == tmpl.get(0).getVersion())) {
			throw new IllegalArgumentException("Not adding keys and version matches existing?");
		}

		if (replace && (keys.get(0).getVersion() != tmpl.get(0).getVersion())) {
			throw new IllegalArgumentException("Replacing keys and versions don't match existing?");
		}

		// Construct APDU
		int P1 = 0x00; // New key in single command unless replace
		if (replace)
			P1 = keys.get(0).getVersion();

		int P2 = keys.get(0).getID();
		if (keys.size() > 1)
			P2 |= 0x80;

		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		try {
			// New key version
			bo.write(keys.get(0).getVersion());
			// Key data
			for (GPKey k: keys) {
				if (scpMajorVersion == 1) {
					bo.write(encodeKey(k, staticKeys.getKey(KeyType.KEK), true));
				} else if (scpMajorVersion == 2) {
					bo.write(encodeKey(k, wrapper.sessionKeys.getKey(KeyType.KEK), true));
				} else if (scpMajorVersion == 3) {
					bo.write(encodeKey(k, wrapper.sessionKeys.getKey(KeyType.KEK), true));
				} else
					throw new IllegalStateException("Unknown SCP version: " + scpMajorVersion);
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		CommandAPDU command = new CommandAPDU(CLA_GP, INS_PUT_KEY, P1, P2, bo.toByteArray());
		ResponseAPDU response = transmit(command);
		check(response,"PUT KEY failed");
	}


	private byte[] getConcatenatedStatus(int p1, byte[] data) throws CardException, GPException {
		CommandAPDU getStatus = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, 0x00, data);
		ResponseAPDU response = transmit(getStatus);
		int sw = response.getSW();
		if ((sw != ISO7816.SW_NO_ERROR) && (sw != 0x6310)) {
			return response.getData(); // Should be empty
		}
		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		try {
			bo.write(response.getData());

			while (response.getSW() == 0x6310) {
				getStatus = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, 0x01, data);
				response = transmit(getStatus);

				bo.write(response.getData());

				sw = response.getSW();
				if ((sw != ISO7816.SW_NO_ERROR) && (sw != 0x6310)) {
					throw new CardException("Get Status failed, SW: " + GPUtils.swToString(sw));
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return bo.toByteArray();
	}


	/**
	 * Get card status. Perform all possible variants of the get status command
	 * and return all entries reported by the card in an AIDRegistry.
	 *
	 * @return registry with all entries on the card
	 * @throws CardException
	 *             in case of communication errors
	 * @throws GPException
	 */
	private AIDRegistry getStatus() throws CardException, GPException {
		AIDRegistry registry = new AIDRegistry();
		int[] p1s = { 0x80, 0x40 };
		for (int p1 : p1s) {
			// parse data no sub-AID
			int index = 0;
			byte[] data = getConcatenatedStatus(p1, new byte[] { 0x4F, 0x00 });
			while (index < data.length) {
				int len = data[index++];
				AID aid = new AID(data, index, len);
				index += len;
				int life_cycle = data[index++];
				int privileges = data[index++];

				AIDRegistryEntry.Kind kind = AIDRegistryEntry.Kind.IssuerSecurityDomain;
				if (p1 == 0x40) {
					if ((privileges & 0x80) == 0) {
						kind = AIDRegistryEntry.Kind.Application;
					} else {
						kind = AIDRegistryEntry.Kind.SecurityDomain;
					}
				}

				AIDRegistryEntry entry = new AIDRegistryEntry(aid, life_cycle, privileges, kind);
				registry.add(entry);
			}
		}
		// Order is important here, so that ExM info would get to the set later
		p1s = new int[] { 0x20, 0x10 };
		for (int p1 : p1s) {
			int index = 0;
			byte[] data = getConcatenatedStatus(p1, new byte[] { 0x4F, 0x00 });
			while (index < data.length) {
				int len = data[index++];
				AID aid = new AID(data, index, len);
				index += len;
				AIDRegistryEntry entry = new AIDRegistryEntry(aid, data[index++], data[index++],
						p1 == 0x10 ? AIDRegistryEntry.Kind.ExecutableLoadFilesAndModules : AIDRegistryEntry.Kind.ExecutableLoadFiles);
				if (p1 == 0x10) {
					int num = data[index++];
					for (int i = 0; i < num; i++) {
						len = data[index++];
						aid = new AID(data, index, len);
						index += len;
						entry.addExecutableAID(aid);
					}
				}
				registry.add(entry);
			}
		}
		return registry;
	}


	private static void check(ResponseAPDU r, String msg) throws GPException {
		int sw = r.getSW();
		if (sw != ISO7816.SW_NO_ERROR) {
			throw new GPException(sw, msg);
		}
	}

	public static class SCP0102Wrapper extends SCPWrapper {

		private byte[] icv = null;
		private byte[] ricv = null;
		private int scp = 0;

		private final ByteArrayOutputStream rMac = new ByteArrayOutputStream();

		private boolean icvEnc = false;

		private boolean preAPDU = false;
		private boolean postAPDU = false;



		private SCP0102Wrapper(GPKeySet sessionKeys, int scp, EnumSet<APDUMode> securityLevel, byte[] icv, byte[] ricv) {
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

		public CommandAPDU wrap(CommandAPDU command) throws CardException {

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
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			} catch (NoSuchPaddingException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			} catch (InvalidKeyException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			} catch (InvalidAlgorithmParameterException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			} catch (IllegalBlockSizeException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			} catch (BadPaddingException e) {
				throw new RuntimeException("APDU wrapping failed", e);
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

		private SCP03Wrapper(GPKeySet sessionKeys, int scp, EnumSet<APDUMode> securityLevel, byte[] icv, byte[] ricv) {
			this.sessionKeys = sessionKeys;
			// initialize chaining value.
			System.arraycopy(GPCrypto.null_bytes_16, 0, chaining_value, 0, GPCrypto.null_bytes_16.length);
			// initialize encryption counter.
			System.arraycopy(GPCrypto.null_bytes_16, 0, encryption_counter, 0, GPCrypto.null_bytes_16.length);

			setSecurityLevel(securityLevel);
		}
		@Override
		protected CommandAPDU wrap(CommandAPDU command) throws CardException {
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
			} catch (IOException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			}
			catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			}
			catch (NoSuchPaddingException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			}
			catch (InvalidKeyException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			}
			catch (IllegalBlockSizeException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			}
			catch (BadPaddingException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			}
			catch (InvalidAlgorithmParameterException e) {
				throw new RuntimeException("APDU wrapping failed", e);
			}
		}

		@Override
		protected ResponseAPDU unwrap(ResponseAPDU response) throws GPException {
			return response;
		}
	}

	public static abstract class SCPWrapper {
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
			int res = GlobalPlatform.defaultLoadSize; // 255
			if (mac)
				res = res - 8;
			if (enc)
				res = res - 8;
			return res;
		}
		protected abstract CommandAPDU wrap(CommandAPDU command) throws CardException;
		protected abstract ResponseAPDU unwrap(ResponseAPDU response) throws GPException;
	}
}
