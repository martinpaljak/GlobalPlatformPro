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
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import openkms.gp.KeySet.Key;
import openkms.gp.KeySet.KeyDiversification;
import openkms.gp.KeySet.KeyType;


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

	// Either 1 or 2
	private int scpMajorVersion = 0;

	private static final byte[] iv_null_bytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	private static final IvParameterSpec iv_null = new IvParameterSpec(iv_null_bytes);

	public static final int defaultLoadSize = 255; // TODO: Check CardData
	private SecureChannelWrapper wrapper = null;
	private KeySet staticKeys = null;
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
		this.verboseTo = out;
	}
	protected void verbose(String s) {
		if (!beVerbose())
			return;
		verboseTo.flush();
		verboseTo.println(s);
		verboseTo.flush();
	}

	public void setStrict(boolean strict) {
		this.strict = strict;
	}

	public void imFeelingLucky() throws CardException, GPException {
		select(null);
		KeySet ks = new KeySet(GlobalPlatformData.defaultKey, GlobalPlatformData.suggestDiversification(getCPLC()));
		openSecureChannel(ks, SCP_ANY, EnumSet.of(APDUMode.MAC));
	}

	protected void printStrictWarning(String message) throws GPException {
		message = "STRICT WARNING: "+ message;
		if (strict) {
			throw new GPException(message);
		} else {
			System.err.println(message);
		}
	}

	private int getGPCLA() {
		if (wrapper != null && wrapper.doesMAC())
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

		if (resp.getSW() == 0x6A82) {
			printStrictWarning("SELECT ISD returned 6A82 - unfused JCOP?");
		}
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


	public List<KeySet.Key> getKeyInfoTemplate() throws CardException, GPException {
		// Key Information Template
		CommandAPDU command = new CommandAPDU(getGPCLA(), ISO7816.INS_GET_DATA, 0x00, 0xE0, 256);
		ResponseAPDU resp = always_transmit(command);

		if (resp.getSW() == ISO7816.SW_CLA_NOT_SUPPORTED) {
			command = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_GET_DATA, 0x00, 0xE0, 256);
			resp = always_transmit(command);
		}
		if (resp.getSW() == ISO7816.SW_NO_ERROR) {
			return GlobalPlatformData.get_key_template_list(resp.getData(), SHORT_0);
		} else {
			verbose("GET DATA(Key Information Template) not supported");
		}
		return GlobalPlatformData.get_key_template_list(null, SHORT_0);
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
		List<Key> key_templates = getKeyInfoTemplate();
		if (key_templates != null && key_templates.size() > 0) {
			GlobalPlatformData.pretty_print_key_template(key_templates, System.out);
		}

		System.out.println("***** GET DATA:");

		// Issuer Identification Number (IIN)
		CommandAPDU command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0x42, 256);
		ResponseAPDU resp = channel.transmit(command);
		if (resp.getSW() == 0x9000) {
			System.out.println("IIN " + LoggingCardTerminal.encodeHexString(resp.getData()));
		} else {
			System.out.println("GET DATA(IIN) not supported");
		}

		// Card Image Number (CIN)
		command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0x45, 256);
		resp = channel.transmit(command);
		if (resp.getSW() == 0x9000) {
			System.out.println("CIN " + LoggingCardTerminal.encodeHexString(resp.getData()));
		} else {
			System.out.println("GET DATA(CIN) not supported");
		}

		// Sequence Counter of the default Key Version Number
		command = new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, 0x00, 0xC1, 256);
		resp = channel.transmit(command);
		if (resp.getSW() == 0x9000) {
			byte [] ssc = resp.getData();
			TLVUtils.expectTag(ssc, SHORT_0, (byte) 0xC1);
			System.out.println("SSC " + LoggingCardTerminal.encodeHexString(TLVUtils.getTLVValueAsBytes(ssc, SHORT_0)));
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
	public void openSecureChannel(KeySet staticKeys, int scpVersion, EnumSet<APDUMode> securityLevel)
			throws CardException, GPException {

		if (sdAID == null)
			throw new IllegalStateException("No selected ISD!");

		this.staticKeys = staticKeys;
		KeySet sessionKeys = null;

		// check for diversification
		if (Arrays.equals(staticKeys.getKey(KeyType.MAC), GlobalPlatformData.defaultKey) && strict) {
			if (GlobalPlatformData.suggestDiversification(getCPLC()) != KeyDiversification.NONE
					&& !staticKeys.needsDiversity() && staticKeys.getKeyVersion() == 0x00)
				printStrictWarning("Card probably requires EMV diversification but no diversification specified!");
		}

		if ((scpVersion < SCP_ANY) || (scpVersion > SCP_02_1B)) {
			throw new IllegalArgumentException("Invalid SCP version.");
		}

		if ((scpVersion == SCP_02_0A) || (scpVersion == SCP_02_0B) || (scpVersion == SCP_02_1A) || (scpVersion == SCP_02_1B)) {
			throw new IllegalArgumentException("Implicit secure channels cannot be initialized explicitly (use the constructor).");
		}

		// ENC requires MAC
		if (securityLevel.contains(APDUMode.ENC))
			securityLevel.add(APDUMode.MAC);

		// Parameters check done.
		byte[] rand = new byte[8];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(rand);

		// P1 key version (SCP1)
		// P2 either key ID (SCP01) or 0 (SCP2)
		// TODO: use it here for KeyID?
		CommandAPDU initUpdate = new CommandAPDU(CLA_GP, INS_INITIALIZE_UPDATE, staticKeys.getKeyVersion(), staticKeys.getKeyID(), rand);

		ResponseAPDU response = channel.transmit(initUpdate);
		int sw = response.getSW();

		// Detect and report locked cards in a more sensible way.
		if ((sw == ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED) || (sw == ISO7816.SW_AUTHENTICATION_METHOD_BLOCKED)) {
			throw new GPException(sw, "INITIALIZE UPDATE failed, card LOCKED?");
		}

		// Detect all other errors
		check(response, "INITIALIZE UPDATE failed");

		byte[] update_response = response.getData();
		if (update_response.length != 28) {
			throw new GPException("Wrong INITIALIZE UPDATE response length: " + update_response.length);
		}
		// Set default SCP version based on major version
		if (scpVersion == SCP_ANY) {
			scpVersion = update_response[11] == 2 ? SCP_02_15 : SCP_01_05;
		}
		scpMajorVersion = (scpVersion < SCP_02_04) ? 1 : 2;
		if (scpMajorVersion != update_response[11]) {
			throw new GPException("Secure Channel Protocol version mismatch: " + scpMajorVersion + " vs " + update_response[11]);
		}
		// Remove RMAC if SCP01 TODO: this should be generic sanitizer somewhere
		if (scpMajorVersion == 1)
			securityLevel.remove(APDUMode.RMAC);

		verbose("Using SCP0" + scpMajorVersion + " with static version " + (update_response[10] & 0xff) + " keys: " + staticKeys);

		// Only diversify default key sets that require it.
		if ((staticKeys.getKeyVersion() == 0) || (staticKeys.getKeyVersion() == 255)) {
			if (staticKeys.needsDiversity()) {
				staticKeys.diversify(update_response);
				verbose("Diversififed keys: " + staticKeys);
			}
		}

		// If using explicit key version, it must match.
		if ((staticKeys.getKeyVersion() > 0) && ((update_response[10] & 0xff) != staticKeys.getKeyVersion())) {
			throw new GPException("Key set mismatch.");
		}

		if (scpMajorVersion == 1) {
			sessionKeys = deriveSessionKeysSCP01(staticKeys, rand, update_response);
		} else if (scpMajorVersion == 2) {
			byte [] seq = Arrays.copyOfRange(update_response, 12, 14);
			sessionKeys = deriveSessionKeysSCP02(staticKeys, seq, false);
		} else {
			throw new GPException("SCP03 is still unexplored");
		}
		verbose("Session keys: " + sessionKeys);


		ByteArrayOutputStream bo = new ByteArrayOutputStream();

		try {
			bo.write(rand);
			bo.write(update_response, 12, 8);
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}

		byte[] myCryptogram = GPUtils.mac_3des(sessionKeys.getKey(KeyType.ENC), GPUtils.pad80(bo.toByteArray()), iv_null_bytes);

		byte[] cardCryptogram = new byte[8];
		System.arraycopy(update_response, 20, cardCryptogram, 0, 8);
		if (!Arrays.equals(cardCryptogram, myCryptogram)) {
			throw new GPException("Card cryptogram invalid.\nExp: " + GPUtils.byteArrayToString(cardCryptogram) + "\nAct: "+GPUtils.byteArrayToString(myCryptogram));
		}

		try {
			bo.reset();
			bo.write(update_response, 12, 8);
			bo.write(rand);
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}

		byte[] authData = GPUtils.mac_3des(sessionKeys.getKey(KeyType.ENC), GPUtils.pad80(bo.toByteArray()), iv_null_bytes);

		wrapper = new SecureChannelWrapper(sessionKeys, scpVersion, EnumSet.of(APDUMode.MAC), null, null);

		int P1 = APDUMode.getSetValue(securityLevel);
		CommandAPDU externalAuthenticate = new CommandAPDU(CLA_MAC, ISO7816.INS_EXTERNAL_AUTHENTICATE_82, P1, 0, authData);
		response = transmit(externalAuthenticate);

		check(response, "External authenticate failed");

		wrapper.setSecurityLevel(securityLevel);
		if (securityLevel.contains(APDUMode.RMAC)) {
			wrapper.ricv = new byte[8];
			System.arraycopy(wrapper.icv, 0, wrapper.ricv, 0, 8);
		}
	}

	private KeySet deriveSessionKeysSCP01(KeySet staticKeys, byte[] hostRandom, byte[] cardResponse) {
		byte[] derivationData = new byte[16];

		System.arraycopy(cardResponse, 16, derivationData, 0, 4);
		System.arraycopy(hostRandom, 0, derivationData, 4, 4);
		System.arraycopy(cardResponse, 12, derivationData, 8, 4);
		System.arraycopy(hostRandom, 4, derivationData, 12, 4);
		KeySet sessionKeys = new KeySet();

		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			for (KeyType v: KeyType.values()) {
				if (v == KeyType.RMAC) continue;
				cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(staticKeys.get3DES(v), "DESede"));
				sessionKeys.setKey(v, cipher.doFinal(derivationData));
			}
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

		// KEK is the same
		sessionKeys.setKey(KeyType.KEK, staticKeys.getKey(KeyType.KEK));
		return sessionKeys;
	}

	private KeySet deriveSessionKeysSCP02(KeySet staticKeys, byte[] sequence, boolean implicitChannel) throws CardException {
		KeySet sessionKeys = new KeySet();

		try {
			Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");

			byte[] derivationData = new byte[16];
			System.arraycopy(sequence, 0, derivationData, 2, 2);

			byte[] constantMAC = new byte[] { (byte) 0x01, (byte) 0x01 };
			System.arraycopy(constantMAC, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(staticKeys.get3DES(KeyType.MAC), "DESede"), iv_null);
			sessionKeys.setKey(KeyType.MAC, cipher.doFinal(derivationData));

			// TODO: is this correct? - increment by one for all other than C-MAC
			if (implicitChannel) {
				TLVUtils.buffer_increment(derivationData, (short)2, (short)2);
			}


			byte[] constantRMAC = new byte[] { (byte) 0x01, (byte) 0x02 };
			System.arraycopy(constantRMAC, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(staticKeys.get3DES(KeyType.MAC), "DESede"), iv_null);
			sessionKeys.setKey(KeyType.RMAC, cipher.doFinal(derivationData));;


			byte[] constantENC = new byte[] { (byte) 0x01, (byte) 0x82 };
			System.arraycopy(constantENC, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(staticKeys.get3DES(KeyType.ENC), "DESede"), iv_null);
			sessionKeys.setKey(KeyType.ENC, cipher.doFinal(derivationData));

			byte[] constantDEK = new byte[] { (byte) 0x01, (byte) 0x81 };
			System.arraycopy(constantDEK, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(staticKeys.get3DES(KeyType.KEK), "DESede"), iv_null);
			sessionKeys.setKey(KeyType.KEK, cipher.doFinal(derivationData));

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
	public void installAndMakeSelecatable(AID packageAID, AID appletAID, AID instanceAID, byte privileges, byte[] installParams,
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
			deleteAID(def, deps);
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
	private byte[] encodeKey(KeySet.Key key, byte []kek, boolean withCheck) {
		try {
			ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
			// Only DES at the moment
			bytearrayoutputstream.write(0x80);
			// Length
			bytearrayoutputstream.write(16);
			// Encrypt key with KEK
			Cipher cipher;
			cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(GPUtils.getKey(kek, 24), "DESede"));
			bytearrayoutputstream.write(cipher.doFinal(key.getValue(), 0, 16));
			if (withCheck) {
				// key check value, 3 bytes with new key over null bytes
				bytearrayoutputstream.write(3);
				SecretKeySpec ky = new SecretKeySpec(GPUtils.getKey(key.getValue(), 24), "DESede");
				cipher.init(Cipher.ENCRYPT_MODE, ky);
				byte check[] = cipher.doFinal(iv_null_bytes);
				bytearrayoutputstream.write(check, 0, 3);
			} else {
				bytearrayoutputstream.write(0);
			}
			return bytearrayoutputstream.toByteArray();
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


	public void putKeys(List<KeySet.Key> keys, boolean replace) throws GPException, CardException {
		if (keys.size() < 1 || keys.size() > 3)
			throw new IllegalArgumentException("Can add keys up to 3 at a time");
		if (keys.size() > 1) {
			for (int i = 1; i < keys.size(); i++) {
				if (keys.get(i-1).getID() != keys.get(i).getID() -1)
					throw new IllegalArgumentException("Key ID-s of multiple keys must be sequential!");
			}
		}
		// Check if factory keys
		List<Key> tmpl = getKeyInfoTemplate();
		if ((tmpl.get(0).getVersion() < 1 || tmpl.get(0).getVersion() > 0x7F) && replace) {
			printStrictWarning("Trying to replace factory keys? Is this a virgin card?");
		}

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
			for (Key k: keys) {
				if (scpMajorVersion == 1) {
					bo.write(encodeKey(k, staticKeys.get3DES(KeyType.KEK), true));
				} else if (scpMajorVersion == 2) {
					bo.write(encodeKey(k, wrapper.sessionKeys.get3DES(KeyType.KEK), true));
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
		p1s = new int[] { 0x10, 0x20 };
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

	public static class SecureChannelWrapper {
		private KeySet sessionKeys = null;
		private byte[] icv = null;
		private byte[] ricv = null;
		private int scp = 0;

		private final ByteArrayOutputStream rMac = new ByteArrayOutputStream();

		private boolean icvEnc = false;

		private boolean preAPDU = false;
		private boolean postAPDU = false;

		private boolean mac = false;
		private boolean enc = false;
		private boolean rmac = false;

		private SecureChannelWrapper(KeySet sessionKeys, int scp, EnumSet<APDUMode> securityLevel, byte[] icv, byte[] ricv) {
			this.sessionKeys = sessionKeys;
			this.icv = icv;
			this.ricv = ricv;
			setSCPVersion(scp);
			setSecurityLevel(securityLevel);
		}

		public void setSecurityLevel(EnumSet<APDUMode> securityLevel) {
			mac = securityLevel.contains(APDUMode.MAC);
			enc = securityLevel.contains(APDUMode.ENC);
			rmac = securityLevel.contains(APDUMode.RMAC);
		}

		protected boolean doesMAC() {
			return mac;
		}

		protected int getBlockSize() {
			int res = GlobalPlatform.defaultLoadSize; // 255
			if (mac)
				res = res - 8;
			if (enc)
				res = res - 8;
			return res;
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

		private byte clearBits(byte b, byte mask) {
			return (byte) ((b & ~mask) & 0xFF);
		}

		private byte setBits(byte b, byte mask) {
			return (byte) ((b | mask) & 0xFF);
		}

		private CommandAPDU wrap(CommandAPDU command) throws CardException {

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
							c = Cipher.getInstance("DESede/ECB/NoPadding");
							c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKeys.get3DES(KeyType.MAC), "DESede"));
						} else {
							c = Cipher.getInstance("DES/ECB/NoPadding");
							c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKeys.getDES(KeyType.MAC), "DES"));
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
						icv = GPUtils.mac_3des(sessionKeys.getKey(KeyType.MAC), GPUtils.pad80(t.toByteArray()), icv);
					} else {
						icv = GPUtils.mac_des_3des(sessionKeys.getKey(KeyType.MAC), GPUtils.pad80(t.toByteArray()), icv);
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
							byte[] x = GPUtils.pad80(t.toByteArray());
							t.reset();
							t.write(x);
						}
					} else {
						t.write(GPUtils.pad80(origData));
					}
					newLc += t.size() - origData.length;

					Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
					c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKeys.get3DES(KeyType.ENC), "DESede"), iv_null);
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

		private ResponseAPDU unwrap(ResponseAPDU response) throws GPException {
			if (rmac) {
				if (response.getData().length < 8) {
					throw new RuntimeException("Wrong response length (too short).");
				}
				int respLen = response.getData().length - 8;
				rMac.write(respLen);
				rMac.write(response.getData(), 0, respLen);
				rMac.write(response.getSW1());
				rMac.write(response.getSW2());

				ricv = GPUtils.mac_des_3des(sessionKeys.getKey(KeyType.RMAC), GPUtils.pad80(rMac.toByteArray()), ricv);

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

}
