/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2016 Martin Paljak, martin@martinpaljak.net
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import javax.crypto.Cipher;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CardTerminals.State;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

import com.google.common.base.Joiner;

import apdu4j.APDUReplayProvider;
import apdu4j.HexUtils;
import apdu4j.LoggingCardTerminal;
import apdu4j.TerminalManager;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import pro.javacard.gp.GPData.KeyType;
import pro.javacard.gp.GPKeySet.Diversification;
import pro.javacard.gp.GPKeySet.GPKey;
import pro.javacard.gp.GPKeySet.GPKey.Type;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPRegistryEntry.Privileges;
import pro.javacard.gp.GlobalPlatform.APDUMode;
import pro.javacard.gp.GlobalPlatform.GPSpec;


public final class GPTool {

	private final static String OPT_APDU = "apdu";
	private final static String OPT_APPLET = "applet"; // can always be shortened, so -app is valid
	private final static String OPT_BS = "bs";
	private final static String OPT_CAP = "cap";
	private final static String OPT_CREATE = "create";
	private final static String OPT_DEBUG = "debug";
	private final static String OPT_DEFAULT = "default";
	private final static String OPT_DELETE = "delete";
	private final static String OPT_DOMAIN = "domain";
	private final static String OPT_DUMP = "dump";
	private final static String OPT_EMV = "emv";
	private final static String OPT_FORCE = "force";
	private final static String OPT_INFO = "info";
	private final static String OPT_INITIALIZED = "initialized";
	private final static String OPT_INSTALL = "install";
	private final static String OPT_KCV = "kcv";
	private final static String OPT_KEY = "key";
	private final static String OPT_KEY_ENC = "key-enc";
	private final static String OPT_KEY_ID = "keyid";
	private final static String OPT_KEY_KEK = "key-kek";
	private final static String OPT_KEY_MAC = "key-mac";
	private final static String OPT_KEY_VERSION = "keyver";
	private final static String OPT_LIST = "list";
	private final static String OPT_LIST_PRIVS = "list-privs";
	private final static String OPT_LOAD = "load";
	private final static String OPT_LOCK = "lock";
	private final static String OPT_LOCK_APPLET = "lock-applet";
	private final static String OPT_LOCK_CARD = "lock-card";
	private final static String OPT_MAKE_DEFAULT = "make-default";
	private final static String OPT_NEW_KEY_VERSION = "new-keyver";
	private final static String OPT_OP201 = "op201";
	private final static String OPT_PACKAGE = "package";
	private final static String OPT_PARAMS = "params";
	private final static String OPT_PKG = "pkg";
	private final static String OPT_PRIVS = "privs";
	private final static String OPT_READER = "reader";
	private final static String OPT_RELAX = "relax";
	private final static String OPT_REPLAY = "replay";
	private final static String OPT_SC_MODE = "mode";
	private final static String OPT_SCP = "scp";
	private final static String OPT_SDAID = "sdaid";
	private final static String OPT_SECURE_APDU = "secure-apdu";
	private final static String OPT_SECURED = "secured";
	private final static String OPT_STORE_DATA = "store-data";
	private final static String OPT_TERMINALS = "terminals";
	private final static String OPT_TERMINATE = "terminate";
	private final static String OPT_UNINSTALL = "uninstall";
	private final static String OPT_UNLOCK = "unlock";
	private final static String OPT_UNLOCK_APPLET = "unlock-applet";
	private final static String OPT_UNLOCK_CARD = "unlock-card";
	private final static String OPT_VERBOSE = "verbose";
	private final static String OPT_VERSION = "version";
	private final static String OPT_VIRGIN = "virgin";
	private final static String OPT_VISA2 = "visa2";


	private static OptionSet parseArguments(String[] argv) throws IOException {
		OptionSet args = null;
		OptionParser parser = new OptionParser();

		// Generic options
		parser.acceptsAll(Arrays.asList("V", OPT_VERSION), "Show information about the program");
		parser.acceptsAll(Arrays.asList("h", "help"), "Shows this help string").forHelp();
		parser.acceptsAll(Arrays.asList("d", OPT_DEBUG), "Show PC/SC and APDU trace");
		parser.acceptsAll(Arrays.asList("v", OPT_VERBOSE), "Be verbose about operations");
		parser.acceptsAll(Arrays.asList("r", OPT_READER), "Use specific reader").withRequiredArg();
		parser.acceptsAll(Arrays.asList("l", OPT_LIST), "List the contents of the card");
		parser.acceptsAll(Arrays.asList("i", OPT_INFO), "Show information");
		parser.acceptsAll(Arrays.asList("a", OPT_APDU), "Send raw APDU (hex)").withRequiredArg().withValuesConvertedBy(ArgMatchers.hex());
		parser.acceptsAll(Arrays.asList("s", OPT_SECURE_APDU), "Send raw APDU (hex) via SCP").withRequiredArg().withValuesConvertedBy(ArgMatchers.hex());
		parser.acceptsAll(Arrays.asList("f", OPT_FORCE), "Force operation");
		parser.accepts(OPT_DUMP, "Dump APDU communication to <File>").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_REPLAY, "Replay APDU responses from <File>").withRequiredArg().ofType(File.class);

		// Special options
		parser.accepts(OPT_RELAX, "Relaxed error checking");
		parser.accepts(OPT_TERMINALS, "Use PC/SC provider from <jar:class>").withRequiredArg();


		// Applet operation options
		parser.accepts(OPT_CAP, "Use a CAP file as source").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_LOAD, "Load a CAP file").withRequiredArg().ofType(File.class);

		parser.accepts(OPT_INSTALL, "Install applet(s) from CAP").withOptionalArg().ofType(File.class);
		parser.accepts(OPT_PARAMS, "Installation parameters").withRequiredArg().withValuesConvertedBy(ArgMatchers.hex());
		parser.accepts(OPT_PRIVS, "Specify privileges for installation").withRequiredArg();
		parser.accepts(OPT_LIST_PRIVS, "List known privileges");

		parser.accepts(OPT_UNINSTALL, "Uninstall applet/package").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_DEFAULT, "Indicate Default Selected privilege");
		parser.accepts(OPT_TERMINATE, "Indicate Card Lock+Terminate privilege");
		parser.accepts(OPT_DOMAIN, "Create supplementary security domain").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.accepts(OPT_LOCK_APPLET, "Lock specified applet").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.accepts(OPT_UNLOCK_APPLET, "Unlock specified applet").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.accepts(OPT_LOCK_CARD, "Lock card");
		parser.accepts(OPT_UNLOCK_CARD, "Unlock card");
		parser.accepts(OPT_SECURED, "Transition SD to SECURED state").withOptionalArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.accepts(OPT_INITIALIZED, "Transition SD to INITIALIZED state").withOptionalArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.accepts(OPT_STORE_DATA, "STORE DATA to applet").withRequiredArg().withValuesConvertedBy(ArgMatchers.hex());

		parser.accepts(OPT_MAKE_DEFAULT, "Make AID the default").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());

		parser.accepts(OPT_DELETE, "Delete applet/package").withOptionalArg().withValuesConvertedBy(ArgMatchers.aid());

		parser.accepts(OPT_CREATE, "Create new instance of an applet").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.accepts(OPT_APPLET, "Applet AID").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.acceptsAll(Arrays.asList(OPT_PKG, OPT_PACKAGE), "Package AID").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());

		// Key options
		parser.accepts(OPT_KEY, "Specify card (master) key").withRequiredArg().withValuesConvertedBy(ArgMatchers.key());
		parser.accepts(OPT_KCV, "Specify key check value").withRequiredArg().withValuesConvertedBy(ArgMatchers.hex());

		parser.accepts(OPT_KEY_MAC, "Specify MAC key").withRequiredArg().withValuesConvertedBy(ArgMatchers.key());
		parser.accepts(OPT_KEY_ENC, "Specify ENC key").withRequiredArg().withValuesConvertedBy(ArgMatchers.key());
		parser.accepts(OPT_KEY_KEK, "Specify KEK key").withRequiredArg().withValuesConvertedBy(ArgMatchers.key());

		parser.accepts(OPT_EMV, "Use EMV diversification");
		parser.accepts(OPT_VISA2, "Use VISA2 diversification");

		parser.accepts(OPT_KEY_ID, "Specify key ID").withRequiredArg().ofType(Integer.class);
		parser.accepts(OPT_KEY_VERSION, "Specify key version").withRequiredArg().ofType(Integer.class);

		parser.accepts(OPT_LOCK, "Set new key").withRequiredArg().withValuesConvertedBy(ArgMatchers.keyset());
		parser.accepts(OPT_UNLOCK, "Set default key");
		parser.accepts(OPT_SCP, "Force the use of SCP0X").withRequiredArg().ofType(Integer.class);
		parser.accepts(OPT_NEW_KEY_VERSION, "key version for the new key").withRequiredArg().ofType(Integer.class);

		parser.accepts(OPT_VIRGIN, "Card has virgin keys");

		// General GP options
		parser.accepts(OPT_SC_MODE, "Secure channel to use (mac/enc/clr)").withRequiredArg().withValuesConvertedBy(ArgMatchers.mode());;
		parser.accepts(OPT_BS, "maximum APDU payload size").withRequiredArg().ofType(Integer.class);
		parser.accepts(OPT_OP201, "Enable OpenPlatform 2.0.1 mode");

		parser.accepts(OPT_SDAID, "ISD AID").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());

		// Parse arguments
		try {
			args = parser.parse(argv);
			// Try to fetch all values so that format is checked before usage
			// for (String s: parser.recognizedOptions().keySet()) {args.valuesOf(s);} // FIXME: screws up logging hack
		} catch (OptionException e) {
			if (e.getCause() != null) {
				System.err.println(e.getMessage() + ": " + e.getCause().getMessage());
			} else {
				System.err.println(e.getMessage());
			}
			System.err.println();
			parser.printHelpOn(System.err);
			System.exit(1);
		}

		// Do the work, based on arguments
		if (args.has("help")) {
			parser.printHelpOn(System.out);
			System.exit(0);
		}

		return args;
	}

	public static void main(String[] argv) throws Exception {

		OptionSet args = parseArguments(argv);

		if (args.has(OPT_VERBOSE)) {
			// Set up slf4j simple in a way that pleases us
			System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
			System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
			System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
			System.setProperty("org.slf4j.simpleLogger.levelInBrackets", "true");
		} else {
			System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");
		}

		if (args.has(OPT_VERSION) || args.has(OPT_VERBOSE) || args.has(OPT_DEBUG) || args.has(OPT_INFO)) {
			String version = GlobalPlatform.getVersion();
			// Append host information
			version += "\nRunning on " + System.getProperty("os.name");
			version += " " + System.getProperty("os.version");
			version += " " + System.getProperty("os.arch");
			version += ", Java " + System.getProperty("java.version");
			version += " by " + System.getProperty("java.vendor");
			System.out.println("GlobalPlatformPro " + version);

			// Test for unlimited crypto
			if (Cipher.getMaxAllowedKeyLength("AES") == 128) {
				System.out.println("Unlimited crypto policy is NOT installed!");
			}
		}

		// Normally assume a single master key
		final SessionKeyProvider keys;

		// Use diversification *for the specified -key* if specified
		Diversification div = Diversification.NONE;
		if (args.has(OPT_VISA2)) {
			div = Diversification.VISA2;
		} else if (args.has(OPT_EMV)) {
			div = Diversification.EMV;
		}

		if (args.has(OPT_KEY) || args.has(OPT_KEY_MAC) || args.has(OPT_KEY_ENC) || args.has(OPT_KEY_KEK)) {
			GPKeySet ks;
			if (args.has(OPT_KEY)) {
				// Specified master key
				GPKey k = (GPKeySet.GPKey)args.valueOf(OPT_KEY);
				if (args.has(OPT_KCV)) {
					final byte [] expected;
					byte [] given = (byte[])args.valueOf(OPT_KCV);
					if (k.getType() == Type.DES3) {
						expected = GPCrypto.kcv_3des(k);
					} else if (k.getType() == Type.AES) {
						expected = GPCrypto.scp03_key_check_value(k);
					} else {
						fail("Don't know how to compute KCV for " + k.getType());
						return; // static analyzer sugar
					}
					// Check KCV
					if (!Arrays.equals(given, expected)) {
						fail("KCV does not match, expected " + HexUtils.bin2hex(expected) + " but given " + HexUtils.bin2hex(given));
					}
				}
				ks = new GPKeySet(k);
			} else {
				System.out.println("ATTENTION: Overriding default keys ...");
				// Override some keys
				ks = new GPKeySet(GPData.defaultKey);
				if (args.has(OPT_KEY_MAC)) {
					ks.setKey(KeyType.MAC, (GPKey) args.valueOf(OPT_KEY_MAC));
				}
				if (args.has(OPT_KEY_ENC)) {
					ks.setKey(KeyType.ENC, (GPKey) args.valueOf(OPT_KEY_ENC));
				}
				if (args.has(OPT_KEY_KEK)) {
					ks.setKey(KeyType.KEK, (GPKey) args.valueOf(OPT_KEY_KEK));
				}
			}
			// Key ID and Version
			if (args.has(OPT_KEY_ID)) {
				ks.setKeyID((int) args.valueOf(OPT_KEY_ID));
			}
			if (args.has(OPT_KEY_VERSION)) {
				ks.setKeyVersion((int) args.valueOf(OPT_KEY_VERSION));
			}
			keys = PlaintextKeys.fromKeySet(ks);
		} else {
			// Use default test key with optional diversification.
			keys = PlaintextKeys.fromMasterKey(GPData.defaultKey, div);
		}

		// Load a CAP file, if specified
		CapFile cap = null;
		if (args.has(OPT_CAP)) {
			File capfile = (File) args.valueOf(OPT_CAP);
			cap = new CapFile(new FileInputStream(capfile));
			if (args.has(OPT_VERBOSE) || args.has(OPT_INFO)) { // TODO: remove -v
				System.out.println("**** CAP info of " + capfile.getName());
				cap.dump(System.out);
			}
		}

		if (args.has(OPT_LIST_PRIVS)) {
			System.out.println("# Known privileges:");
			System.out.println(Joiner.on("\n").join(Privilege.values()));
		}

		// Now actually talk to possible terminals
		try {
			final TerminalFactory tf;

			if (args.has(OPT_REPLAY)) {
				// Replay responses from a file
				// FIXME: use the generic provider interface and drop command line options
				File f = (File) args.valueOf(OPT_REPLAY);
				tf = TerminalFactory.getInstance("PC/SC", new FileInputStream(f), new APDUReplayProvider());
			} else {
				tf = TerminalManager.getTerminalFactory((String)args.valueOf(OPT_TERMINALS));
			}

			CardTerminals terminals = tf.terminals();

			// List terminals if needed
			if (args.has(OPT_DEBUG)) {
				System.out.println("# Detected readers from " + tf.getProvider().getName());
				for (CardTerminal term : terminals.list()) {
					System.out.println((term.isCardPresent() ? "[*] " : "[ ] ") + term.getName());
				}
			}

			// Select terminal(s) to work on
			List<CardTerminal> do_readers;
			if (args.has(OPT_READER) || System.getenv("GP_READER") != null) {
				String reader = System.getenv("GP_READER");
				if (args.has(OPT_READER))
					reader = (String) args.valueOf(OPT_READER);
				CardTerminal t = terminals.getTerminal(reader);
				if (t == null) {
					fail("Reader \"" + reader + "\" not found.");
				}
				do_readers = Arrays.asList(t);
			} else {
				do_readers = terminals.list(State.CARD_PRESENT);
			}

			if (do_readers.size() == 0) {
				fail("No smart card readers with a card found");
			}
			// Work all readers
			for (CardTerminal reader: do_readers) {
				if (do_readers.size() > 1) {
					System.out.println("# " + reader.getName());
				}
				// Wrap with logging if requested
				if (args.has(OPT_DEBUG)) {
					// And with APDU dumping
					OutputStream o = null;
					if (args.has(OPT_DUMP)) {
						File f = (File) args.valueOf(OPT_DUMP);
						o = new FileOutputStream(f);
					}
					reader = LoggingCardTerminal.getInstance(reader, o);
				}

				Card card = null;
				try {
					// Establish connection
					try {
						card = reader.connect("*");
						// Use use apdu4j which by default uses jnasmartcardio
						// which uses real SCardBeginTransaction
						card.beginExclusive();
					} catch (CardException e) {
						System.err.println("Could not connect to " + reader.getName() + ": " + TerminalManager.getExceptionMessage(e));
						continue;
					}

					// GlobalPlatform specific
					GlobalPlatform gp = new GlobalPlatform(card.getBasicChannel());

					if (args.has(OPT_OP201)) {
						gp.setSpec(GPSpec.OP201);
					}
					// Disable strict mode if requested
					gp.setStrict(!args.has(OPT_RELAX));

					// Override block size for stupidly broken readers.
					// See https://github.com/martinpaljak/GlobalPlatformPro/issues/32
					// The name of the option comes from a common abbreviation as well as dd utility
					if (args.has(OPT_BS)) {
						gp.setBlockSize((int)args.valueOf(OPT_BS));
					}
					if (args.has(OPT_INFO) || args.has(OPT_VERBOSE)) {
						System.out.println("Reader: " + reader.getName());
						System.out.println("ATR: " + HexUtils.bin2hex(card.getATR().getBytes()));
						System.out.println("More information about your card:");
						System.out.println("    http://smartcard-atr.appspot.com/parse?ATR="+HexUtils.bin2hex(card.getATR().getBytes()));
						System.out.println();
					}

					// Send all raw APDU-s to the default-selected application of the card
					if (args.has(OPT_APDU)) {
						for (Object s: args.valuesOf(OPT_APDU)) {
							CommandAPDU c = new CommandAPDU((byte[]) s);
							card.getBasicChannel().transmit(c);
						}
					}

					// Talk to the card manager (can be null)
					gp.select((AID) args.valueOf(OPT_SDAID));

					// Fetch some possibly interesting data
					if (args.has(OPT_INFO)) {
						System.out.println("***** Card info:");
						GPData.print_card_info(gp);
					}

					// Authenticate, only if needed
					if (needsAuthentication(args)) {

						EnumSet<APDUMode> mode = GlobalPlatform.defaultMode.clone();
						// Override default mode if needed.
						if (args.has(OPT_SC_MODE)) {
							mode.clear();
							mode.add((GlobalPlatform.APDUMode) args.valueOf(OPT_SC_MODE));
						}

						// Override SCP version
						int scp_version = 0;
						if (args.has(OPT_SCP)) {
							scp_version = (int) args.valueOf(OPT_SCP);
						}

						// Possibly brick the card now, if keys don't match.
						gp.openSecureChannel(keys, null, scp_version, mode);

						// --secure-apdu or -s
						if (args.has(OPT_SECURE_APDU)) {
							for (Object s: args.valuesOf(OPT_SECURE_APDU)) {
								CommandAPDU c = new CommandAPDU((byte[])s);
								gp.transmit(c);
							}
						}

						// --delete <aid> or --delete --default
						if (args.has(OPT_DELETE)) {
							GPRegistry reg = gp.getRegistry();

							if (args.has(OPT_DEFAULT) && reg.getDefaultSelectedAID() != null) {
								if (reg.getDefaultSelectedPackageAID() != null) {
									gp.deleteAID(reg.getDefaultSelectedPackageAID(), true);
								} else {
									System.err.println("Could not identify default selected application!");
								}
							}
							@SuppressWarnings("unchecked")
							List<AID> aids = (List<AID>) args.valuesOf(OPT_DELETE);

							for (AID aid: aids) {
								try {
									// If the AID represents a package or otherwise force is enabled.
									gp.deleteAID(aid, reg.allPackageAIDs().contains(aid) || args.has(OPT_FORCE));
								} catch (GPException e) {
									if (!gp.getRegistry().allAIDs().contains(aid)) {
										System.err.println("Could not delete AID (not present on card): " + aid);
									} else {
										System.err.println("Could not delete AID: " + aid);
										if (e.sw == 0x6985) {
											System.err.println("Deletion not allowed. Some app still active?");
										} else {
											throw e;
										}
									}
								}
							}
						}

						// --uninstall <cap>
						if (args.has(OPT_UNINSTALL)) {
							File capfile = (File) args.valueOf(OPT_UNINSTALL);
							CapFile instcap = new CapFile(new FileInputStream(capfile));
							AID aid = instcap.getPackageAID();
							if (!gp.getRegistry().allAIDs().contains(aid)) {
								System.out.println(aid + " is not present on card!");
							} else {
								gp.deleteAID(aid, true);
								System.out.println(aid + " deleted.");
							}
						}

						// --load <applet.cap>
						if (args.has(OPT_LOAD)) {
							File capfile = (File) args.valueOf(OPT_LOAD);
							CapFile loadcap = new CapFile(new FileInputStream(capfile));

							if (args.has(OPT_VERBOSE)) {
								loadcap.dump(System.out);
							}
							try {
								gp.loadCapFile(loadcap);
							} catch (GPException e) {
								if (e.sw == 0x6985) {
									System.err.println("Applet loading failed. Are you sure the CAP file target is compatible with your card?");
								} else {
									throw e;
								}
							}
						}


						// --install <applet.cap>
						if (args.has(OPT_INSTALL)) {
							final File capfile;
							capfile = (File) args.valueOf(OPT_INSTALL);

							CapFile instcap = new CapFile(new FileInputStream(capfile));

							if (args.has(OPT_VERBOSE)) {
								instcap.dump(System.out);
							}
							// Only install if cap contains a single applet
							if (instcap.getAppletAIDs().size() == 0) {
								fail("No applets in CAP, use --" + OPT_LOAD + " instead");
							}
							if (instcap.getAppletAIDs().size() > 1) {
								fail("CAP contains more than one applet, create instances manually with --" + OPT_LOAD + " and --" + OPT_CREATE);
							}

							GPRegistry reg = gp.getRegistry();
							Privileges privs = getInstPrivs(args);

							// Remove existing default app
							if (args.has(OPT_FORCE) && (reg.getDefaultSelectedAID() != null && privs.has(Privilege.CardReset))) {
								gp.deleteAID(reg.getDefaultSelectedAID(), false);
							}
							// Remove existing load file
							if (args.has(OPT_FORCE) && reg.allPackageAIDs().contains(instcap.getPackageAID())) {
								gp.deleteAID(instcap.getPackageAID(), true);
							}

							try {
								gp.loadCapFile(instcap);
								System.err.println("CAP loaded");
							} catch (GPException e) {
								if (e.sw == 0x6985 || e.sw == 0x6A80) {
									System.err.println("Applet loading failed. Are you sure the CAP file (JC version, packages) is compatible with your card?");
								}
								throw e;
							}

							// Take the applet AID from CAP but allow to override
							AID appaid = instcap.getAppletAIDs().get(0);
							if (args.has(OPT_APPLET)) {
								appaid = (AID) args.valueOf(OPT_APPLET);
							}
							if (args.has(OPT_CREATE)) {
								appaid = (AID) args.valueOf(OPT_CREATE);
							}
							if (gp.getRegistry().allAIDs().contains(appaid)) {
								System.err.println("WARNING: Applet " + appaid + " already present on card");
							}
							gp.installAndMakeSelectable(instcap.getPackageAID(), appaid, null, privs, getInstParams(args), null);
						}

						// --create <aid> (--applet <aid> --package <aid> or --cap <cap>)
						if (args.has(OPT_CREATE)) {
							AID packageAID = null;
							AID appletAID = null;
							// Load from cap if present
							if (cap != null) {
								packageAID = cap.getPackageAID();
								if (cap.getAppletAIDs().size() != 1) {
									throw new IllegalArgumentException("There should be only one applet in CAP. Use --" + OPT_APPLET + " instead.");
								}
								appletAID = cap.getAppletAIDs().get(0);
							}
							// override if needed
							if (args.has(OPT_PACKAGE)) {
								packageAID = (AID) args.valueOf(OPT_PACKAGE);
							}
							if (args.has(OPT_APPLET)) {
								appletAID = (AID) args.valueOf(OPT_APPLET);
							}
							// check
							if (packageAID == null || appletAID == null)
								throw new IllegalArgumentException("Need --" + OPT_PACKAGE + " and --" + OPT_APPLET + " or --" + OPT_CAP);

							// shoot
							AID instanceAID = (AID) args.valueOf(OPT_CREATE);
							gp.installAndMakeSelectable(packageAID, appletAID, instanceAID, getInstPrivs(args), getInstParams(args), null);
						}

						// --domain <AID>
						if (args.has(OPT_DOMAIN)) {
							// Default AID-s
							AID packageAID = new AID("A0000001515350");
							AID appletAID = new AID("A000000151535041");

							// Override if necessary
							if (args.has(OPT_PACKAGE) && args.has(OPT_APPLET)) {
								packageAID = (AID) args.valueOf(OPT_PACKAGE);
								appletAID = (AID) args.valueOf(OPT_APPLET);
							} else {
								System.out.println("Note: using default AID-s for SSD: " + appletAID + " from " + packageAID);
							}
							AID instanceAID = (AID) args.valueOf(OPT_DOMAIN);

							// Extra privileges
							Privileges privs= getInstPrivs(args);
							privs.add(Privilege.SecurityDomain);

							// shoot
							gp.installAndMakeSelectable(packageAID, appletAID, instanceAID, privs, null, null);
						}

						// --store-data <XX>
						if (args.has(OPT_STORE_DATA)) {
							if (args.has(OPT_APPLET)) {
								gp.storeData((AID)args.valueOf(OPT_APPLET), (byte[]) args.valueOf(OPT_STORE_DATA));
							} else {
								System.err.println("Must specify target application with -" + OPT_APPLET);
							}
						}
						// --lock-card
						if (args.has(OPT_LOCK_CARD)) {
							gp.setCardStatus(GPData.lockedStatus);
						}
						// --unlock-card
						if (args.has(OPT_UNLOCK_CARD)) {
							gp.setCardStatus(GPData.securedStatus);
						}
						// --initialized
						if (args.has(OPT_INITIALIZED)) {
							gp.setCardStatus(GPData.initializedStatus);
						}
						// --secured
						if (args.has(OPT_SECURED)) {
							gp.setCardStatus(GPData.securedStatus);
						}

						// --lock-applet <aid>
						if (args.has(OPT_LOCK_APPLET)) {
							gp.lockUnlockApplet((AID) args.valueOf(OPT_LOCK_APPLET), true);
						}

						// --unlock-applet <AID>
						if (args.has(OPT_UNLOCK_APPLET)) {
							gp.lockUnlockApplet((AID) args.valueOf(OPT_UNLOCK_APPLET), false);
						}

						// --list
						if (args.has(OPT_LIST)) {
							String tab = "     ";
							GPRegistry reg = gp.getRegistry();
							System.out.println("# Mode: " + gp.spec); // TODO: expose ?
							for (GPRegistryEntry e : reg) {
								AID aid = e.getAID();
								System.out.print(e.getType().toShortString() + ": " + HexUtils.bin2hex(aid.getBytes()) + " (" + e.getLifeCycleString() + ")");
								if (e.getType() != Kind.IssuerSecurityDomain && args.has(OPT_VERBOSE)) {
									System.out.println(" (" + GPUtils.byteArrayToReadableString(aid.getBytes()) + ")");
								} else {
									System.out.println();
								}

								if (e.getDomain() != null) {
									System.out.println(tab + "Parent:  " + e.getDomain());
								}
								if (e.getType() == Kind.ExecutableLoadFile) {
									GPRegistryEntryPkg pkg = (GPRegistryEntryPkg) e;
									if (pkg.getVersion() != null) {
										System.out.println(tab + "Version: " + pkg.getVersionString());
									}
									for (AID a : pkg.getModules()) {
										System.out.print(tab + "Applet:  " +  HexUtils.bin2hex(a.getBytes()));
										if (args.has(OPT_VERBOSE)) {
											System.out.println(" (" + GPUtils.byteArrayToReadableString(a.getBytes()) + ")");
										} else {
											System.out.println();
										}
									}
								} else {
									GPRegistryEntryApp app = (GPRegistryEntryApp) e;
									if (app.getLoadFile() != null) {
										System.out.println(tab + "From:    " + app.getLoadFile());
									}
									if (!app.getPrivileges().isEmpty()) {
										System.out.println(tab + "Privs:   " + app.getPrivileges());
									}
								}
								System.out.println();
							}
						}

						// --unlock
						if (args.has(OPT_UNLOCK)) {
							// Write default keys
							List<GPKeySet.GPKey> newkeys = new ArrayList<GPKeySet.GPKey>();

							// Fetch the current key information to get the used ID-s.
							List<GPKey> current = gp.getKeyInfoTemplate();
							if (current.size() != 3) {
								throw new GPException("Template has bad length!"); // XXX: move to GlobalPlatform
							}
							// FIXME: new key must adhere to currently used SCP version.
							GPKey new_key = new GPKey(GPData.defaultKeyBytes, gp.getSCPVersion() == 3 ? Type.AES : Type.DES3);

							// FIXME: this looks ugly
							newkeys.add(new GPKeySet.GPKey(01, current.get(0).getID(), new_key));
							newkeys.add(new GPKeySet.GPKey(01, current.get(1).getID(), new_key));
							newkeys.add(new GPKeySet.GPKey(01, current.get(2).getID(), new_key));

							// "add keys" if default factory keys or otherwise virgin card
							// because version FF can not be addressed
							if (args.has(OPT_VIRGIN)) {
								gp.putKeys(newkeys, false);
							} else {
								// normally replace existing keys
								gp.putKeys(newkeys, true);
							}
							System.out.println("Default " + new_key.toStringKey() + " set as master key.");
						}

						// --lock
						if (args.has(OPT_LOCK)) {
							// XXX: this is ugly, we re-use ArgParser only to get diversification method
							PlaintextKeys newkey = (PlaintextKeys) args.valueOf(OPT_LOCK);

							GPKeySet newkeys = new GPKeySet(newkey.master);

							// Diversify if requested.
							if (newkey.diversifier != Diversification.NONE) {
								newkeys = PlaintextKeys.diversify(newkeys, gp.getDiversificationData(), newkey.diversifier, gp.getSCPVersion());
							}

							// FIXME: Check that
							int new_version = 1;

							if (args.has(OPT_NEW_KEY_VERSION)) {
								new_version = (int) args.valueOf(OPT_NEW_KEY_VERSION);
							}
							// Add into a list
							List<GPKeySet.GPKey> updatekeys = new ArrayList<GPKeySet.GPKey>();
							updatekeys.add(new GPKeySet.GPKey(new_version, 01, newkeys.getKey(KeyType.ENC)));
							updatekeys.add(new GPKeySet.GPKey(new_version, 02, newkeys.getKey(KeyType.MAC)));
							updatekeys.add(new GPKeySet.GPKey(new_version, 03, newkeys.getKey(KeyType.KEK)));
							// Add new keys if virgin
							if (args.has(OPT_VIRGIN)) {
								gp.putKeys(updatekeys, false);
							} else {
								// normally replace
								gp.putKeys(updatekeys, true);
							}
							System.out.println("Card locked with: " + newkey.master.toStringKey());
							if (newkey.diversifier!= Diversification.NONE) {
								System.out.println("Remember to use " + newkey.diversifier.name() + " diversification!");
							}
							System.out.println("Write this down, DO NOT FORGET/LOSE IT!");
						}

						// --make-default <aid>
						if (args.has(OPT_MAKE_DEFAULT)) {
							gp.makeDefaultSelected((AID) args.valueOf(OPT_MAKE_DEFAULT));
						}
					}
				} catch (GPException e) {
					if (args.has(OPT_VERBOSE)) {
						e.printStackTrace(System.err);
					}
					// All unhandled GP exceptions halt the program unless it is run with -relax
					if (!args.has(OPT_RELAX)) {
						fail(e.getMessage());
					}
				} catch (CardException e) {
					// Card exceptions skip to the next reader, if available and allowed FIXME broken logic
					continue;
				} finally {
					if (card != null) {
						card.endExclusive();
						card.disconnect(true);
						card = null;
					}
				}
			}
		} catch (CardException e) {
			// Sensible wrapper for the different PC/SC exceptions
			if (TerminalManager.getExceptionMessage(e) != null) {
				System.out.println("PC/SC failure: " + TerminalManager.getExceptionMessage(e));
			} else {
				e.printStackTrace(); // TODO: remove
				fail("CardException, terminating");
			}
		}
		// Other exceptions escape. fin.
		System.exit(0);
	}

	// FIXME: get rid
	private static Privileges getInstPrivs(OptionSet args) {
		Privileges privs = new Privileges();
		if (args.has(OPT_PRIVS)) {
			addPrivs(privs, (String)args.valueOf(OPT_PRIVS));
		}
		if (args.has(OPT_DEFAULT)) {
			privs.add(Privilege.CardReset);
		}
		if (args.has(OPT_TERMINATE)) {
			privs.add(Privilege.CardLock);
			privs.add(Privilege.CardTerminate);
		}
		return privs;
	}

	private static Privileges addPrivs(Privileges privs, String v) {
		String [] parts = v.split(",");
		for (String s: parts) {
			boolean found = false;
			for (Privilege p: Privilege.values()) {
				if (s.trim().equalsIgnoreCase(p.name())) {
					found = true;
					privs.add(p);
					break;
				}
			}
			if (!found) {
				throw new IllegalArgumentException("Unknown privilege: " + s.trim());
			}
		}
		return privs;
	}

	private static byte [] getInstParams(OptionSet args) {
		byte[] params = null;
		if (args.has(OPT_PARAMS)) {
			params = (byte []) args.valueOf(OPT_PARAMS);
			// Simple use: only application parameters without tag, prepend 0xC9
			if (params[0] != (byte) 0xC9) {
				byte [] newparams = new byte[params.length + 2];
				newparams[0] = (byte) 0xC9;
				newparams[1] = (byte) params.length;
				System.arraycopy(params, 0, newparams, 2, params.length);
				params = newparams;
			}
		}
		return params;
	}

	private static boolean needsAuthentication(OptionSet args) {
		if (args.has(OPT_LIST) || args.has(OPT_LOAD) || args.has(OPT_INSTALL))
			return true;
		if (args.has(OPT_DELETE) || args.has(OPT_CREATE))
			return true;
		if (args.has(OPT_LOCK) || args.has(OPT_UNLOCK) || args.has(OPT_MAKE_DEFAULT))
			return true;
		if (args.has(OPT_UNINSTALL) || args.has(OPT_SECURE_APDU) || args.has(OPT_DOMAIN))
			return true;
		if (args.has(OPT_LOCK_CARD) || args.has(OPT_UNLOCK_CARD) || args.has(OPT_LOCK_APPLET) || args.has(OPT_UNLOCK_APPLET))
			return true;
		if (args.has(OPT_STORE_DATA) || args.has(OPT_INITIALIZED) || args.has(OPT_SECURED))
			return true;
		return false;
	}

	private static void fail(String msg) {
		System.err.println(msg);
		System.exit(1);
	}
}
