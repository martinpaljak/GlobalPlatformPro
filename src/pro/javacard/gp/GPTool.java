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
import pro.javacard.gp.GlobalPlatform.APDUMode;

import javax.smartcardio.*;
import javax.smartcardio.CardTerminals.State;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;


public final class GPTool {
	private final static String OPT_INFO = "info";

	private final static String OPT_LIST = "list";
	private final static String OPT_LOCK = "lock";
	private final static String CMD_READERS = "terminals";

	private final static String OPT_INSTALL = "install";
	private final static String OPT_UNINSTALL = "uninstall";
	private final static String OPT_DELETE = "delete";
	private final static String OPT_CREATE = "create";
	private final static String OPT_LOAD = "load";
	private final static String OPT_UNLOCK = "unlock";
	private final static String OPT_MAKE_DEFAULT = "make-default";
	private final static String OPT_APDU = "apdu";
	private final static String OPT_SECURE_APDU = "secure-apdu";
	private final static String OPT_SCP = "scp";
	private final static String OPT_LOCK_APPLET = "lock-applet";
	private final static String OPT_UNLOCK_APPLET = "unlock-applet";

	private final static String OPT_DELETEDEPS = "deletedeps";
	private final static String OPT_DEFAULT = "default";
	private final static String OPT_TERMINATE = "terminate";
	private final static String OPT_SDOMAIN = "sdomain";

	private final static String OPT_CAP = "cap";
	private final static String OPT_APPLET = "applet";
	private final static String OPT_PACKAGE = "package";
	private final static String OPT_DO_ALL_READERS = "all";
	private final static String OPT_NOFIX = "nofix";
	private final static String OPT_PARAMS = "params";

	private final static String OPT_CONTINUE = "skip-error";
	private final static String OPT_RELAX = "relax";
	private final static String OPT_READER = "reader";
	private final static String OPT_VERSION = "version";
	private final static String OPT_SDAID = "sdaid";
	private final static String OPT_DEBUG = "debug";
	private final static String OPT_DUMP = "dump";
	private final static String OPT_REPLAY = "replay";
	private final static String OPT_VERBOSE = "verbose";
	private final static String OPT_REINSTALL = "reinstall";
	private final static String OPT_VIRGIN = "virgin";
	private final static String OPT_MODE = "mode";
	private final static String OPT_BS = "bs";
	private final static String OPT_REMOTEFACTORY = "remote";
	
	private final static String OPT_MAC = "mac";
	private final static String OPT_ENC = "enc";
	private final static String OPT_KEK = "kek";
	private final static String OPT_KEY = "key";
	private final static String OPT_KEY_VERSION = "keyver";
	private final static String OPT_KEY_ID = "keyid";
	private final static String OPT_NEW_KEY_VERSION = "new-keyver";

	private final static String OPT_EMV = "emv";
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
		parser.acceptsAll(Arrays.asList("a", OPT_APDU), "Send raw APDU (hex)").withRequiredArg();
		parser.acceptsAll(Arrays.asList("s", OPT_SECURE_APDU), "Send raw APDU (hex) via SCP").withRequiredArg();
		parser.acceptsAll(Arrays.asList("t", CMD_READERS), "List terminal(s) names");
		
		// Special options
		parser.accepts(OPT_RELAX, "Relaxed error checking");
		parser.accepts(OPT_DO_ALL_READERS, "Work with multiple readers");
		parser.accepts(OPT_NOFIX, "Do not try to fix PCSC/Java/OS issues");
		parser.accepts(OPT_CONTINUE, "Skip errors that cause exceptions");
		parser.accepts(OPT_REMOTEFACTORY, "Use remote PC/SC - an optional argument specifies IP address range and protocol, e.g., tcp://192.168.1.0/24").withOptionalArg().ofType(String.class);
		parser.accepts(OPT_DUMP, "Dump APDU communication to <File>").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_REPLAY, "Replay APDU responses from <File>").withRequiredArg().ofType(File.class);
		
		// Applet operation options
		parser.accepts(OPT_CAP, "Use a CAP file as source").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_LOAD, "Load a CAP file").withRequiredArg().ofType(File.class);
		
		parser.accepts(OPT_INSTALL, "Install applet(s) from CAP").withOptionalArg().ofType(File.class);
		parser.accepts(OPT_PARAMS, "Installation parameters").withRequiredArg();
		
		parser.accepts(OPT_UNINSTALL, "Uninstall applet/package").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_DEFAULT, "Indicate Default Selected privilege");
		parser.accepts(OPT_TERMINATE, "Indicate Card Lock+Terminate privilege");
		parser.accepts(OPT_SDOMAIN, "Indicate Security Domain privilege");
		parser.accepts(OPT_LOCK_APPLET, "Lock specified applet").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.accepts(OPT_UNLOCK_APPLET, "Lock specified applet").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		
		
		parser.accepts(OPT_DELETEDEPS, "Also delete dependencies");
		parser.accepts(OPT_REINSTALL, "Reinstall CAP").withOptionalArg().ofType(File.class);
		parser.accepts(OPT_MAKE_DEFAULT, "Make AID the default").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		
		parser.accepts(OPT_DELETE, "Delete something").requiredIf(OPT_DELETEDEPS).withOptionalArg().withValuesConvertedBy(ArgMatchers.aid());
		
		parser.accepts(OPT_CREATE, "Create new instance of an applet").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.accepts(OPT_APPLET, "Applet AID").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		parser.accepts(OPT_PACKAGE, "Package AID").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		
		// Key options
		parser.accepts(OPT_MAC, "Specify MAC key").withRequiredArg().withValuesConvertedBy(ArgMatchers.key());
		parser.accepts(OPT_ENC, "Specify ENC key").withRequiredArg().withValuesConvertedBy(ArgMatchers.key());
		parser.accepts(OPT_KEK, "Specify KEK key").withRequiredArg().withValuesConvertedBy(ArgMatchers.key());
		parser.accepts(OPT_KEY, "Specify master key").withRequiredArg().withValuesConvertedBy(ArgMatchers.key());
		parser.accepts(OPT_KEY_ID, "Specify key ID").withRequiredArg().ofType(Integer.class);
		parser.accepts(OPT_KEY_VERSION, "Specify key version").withRequiredArg().ofType(Integer.class);
		parser.accepts(OPT_LOCK, "Set new key").withRequiredArg().withValuesConvertedBy(ArgMatchers.keyset());
		
		parser.accepts(OPT_UNLOCK, "Set default key");
		parser.accepts(OPT_SCP, "Force the use of SCP0X").withRequiredArg().ofType(Integer.class);
		parser.accepts(OPT_NEW_KEY_VERSION, "key version for the new key").withRequiredArg().ofType(Integer.class);
		
		parser.accepts(OPT_VIRGIN, "Card has virgin keys");
		
		
		// Key diversification and AID options
		parser.accepts(OPT_EMV, "Use EMV diversification");
		parser.accepts(OPT_VISA2, "Use VISA2 diversification");
		parser.accepts(OPT_MODE, "APDU mode to use (mac/enc/clr)").withRequiredArg().withValuesConvertedBy(ArgMatchers.mode());;
		parser.accepts(OPT_BS, "maximum APDU payload size").withRequiredArg().ofType(Integer.class);
		
		parser.accepts(OPT_SDAID, "ISD AID").withRequiredArg().withValuesConvertedBy(ArgMatchers.aid());
		
		
		// Parse arguments
		try {
			args = parser.parse(argv);
			// Try to fetch all values so that format is checked before usage
			for (String s: parser.recognizedOptions().keySet()) {args.valuesOf(s);}
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
		
		if (args.has(OPT_VERSION)) {
			System.out.println("GlobalPlatformPro " + GlobalPlatform.getVersion());
		}
		
		// Parameters for opening the secure channel
		// Keying options: either a single master or three separate keys
		if (args.has(OPT_KEY) && (args.has(OPT_MAC) || args.has(OPT_ENC) || args.has(OPT_KEK))) {
			System.err.println("If you specify " + OPT_KEY + " do not use other keying options!");
			System.exit(1);
		}
		
		// Normally assume a single master key
		SessionKeyProvider keys;
		// Use diversification if specified
		Diversification div = Diversification.NONE;
		if (args.has(OPT_VISA2)) {
			div = Diversification.VISA2;
		} else if (args.has(OPT_EMV)) {
			div = Diversification.EMV;
		}
		
		if (args.has(OPT_KEY)) {
			// Specified master key
			keys = PlaintextKeys.fromMasterKey((GPKeySet.GPKey)args.valueOf(OPT_KEY), div);
		} else if (args.has(OPT_MAC) && args.has(OPT_ENC) && args.has(OPT_KEK)) {
			// All components specified separately
			GPKeySet ks = new GPKeySet();
			ks.setKey(KeyType.MAC, (GPKeySet.GPKey)args.valueOf(OPT_MAC));
			ks.setKey(KeyType.ENC, (GPKeySet.GPKey)args.valueOf(OPT_ENC));
			ks.setKey(KeyType.KEK, (GPKeySet.GPKey)args.valueOf(OPT_KEK));
			keys = PlaintextKeys.fromKeySet(ks);
		} else {
			// Use default test key with optional diverisifaction.
			keys = PlaintextKeys.fromMasterKey(GPData.defaultKey, div);
		}
		
		// FIXME: somehow expose this.
		//		// Key ID and Version
		//		if (args.has(OPT_KEY_ID)) {
		//			ks.setKeyID((int) args.valueOf(OPT_KEY_ID));
		//		}
		//		if (args.has(OPT_KEY_VERSION)) {
		//			ks.setKeyVersion((int) args.valueOf(OPT_KEY_VERSION));
		//		}
		
		
		// Load a CAP file, if specified
		CapFile cap = null;
		if (args.has(OPT_CAP)) {
			File capfile = (File) args.valueOf(OPT_CAP);
			cap = new CapFile(new FileInputStream(capfile));
			if (args.has(OPT_VERBOSE)) {
				System.out.println("**** CAP info:");
				cap.dump(System.out);
			}
		}
		
		// Now actually talk to possible terminals
		try {
			TerminalFactory tf;
			if (args.has(OPT_REMOTEFACTORY)) {
				tf = TerminalManager.getRemoteTerminalFactory((String)args.valueOf(OPT_REMOTEFACTORY));
				System.out.println("Remote/socket PC/SC used");
			} else {
				tf = TerminalManager.getTerminalFactory(args.has(OPT_NOFIX) ? false : true);
				
				// Replay responses from a file
				if (args.has(OPT_REPLAY)) {
					File f = (File) args.valueOf(OPT_REPLAY);
					tf = TerminalFactory.getInstance("PC/SC", new FileInputStream(f), new APDUReplayProvider());
				}
			}
			
			CardTerminals terminals = tf.terminals();
			
			// List terminals if needed
			if (args.has(OPT_DEBUG)) {
				System.out.println("# Detected readers from " + tf.getProvider().getName());
				for (CardTerminal term : terminals.list()) {
					System.out.println((term.isCardPresent() ? "[*] " : "[ ] ") + term.getName());
				}
			}
			
			// Select terminals to work on
			List<CardTerminal> do_readers;
			if (args.has(OPT_READER)) {
				String reader = (String) args.valueOf(OPT_READER);
				CardTerminal t = terminals.getTerminal(reader);
				if (t == null) {
					System.err.println("Reader \"" + reader + "\" not found.");
					System.exit(1);
				}
				do_readers = Arrays.asList(t);
			} else {
				do_readers = terminals.list(State.CARD_PRESENT);
				if (do_readers.size() > 1 && !args.has(OPT_DO_ALL_READERS)) {
					System.err.println("More than one reader with a card found.");
					System.err.println("Run with --"+OPT_DO_ALL_READERS+" to work with all found cards");
					System.exit(1);
				}
			}
			
			// Work all readers
			for (CardTerminal reader: do_readers) {
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
						card.beginExclusive();
					} catch (CardException e) {
						if (args.has(OPT_CONTINUE) || (args.has(OPT_REMOTEFACTORY))) {
							e.printStackTrace();
							continue;
						} else {
							throw e;
						}
					}
					
					// GlobalPlatform specific
					GlobalPlatform gp = new GlobalPlatform(card.getBasicChannel());
					
					
					// Disable strict mode if requested
					gp.setStrict(!args.has(OPT_RELAX));
					
					// Override block size for stupidly broken readers.
					// See https://github.com/martinpaljak/GlobalPlatformPro/issues/32
					// The name of the option comes from a common abbreviation as well as dd utility
					if (args.has(OPT_BS)) {
						gp.setBlockSize((int)args.valueOf(OPT_BS));
					} else if (args.has(OPT_REMOTEFACTORY)){
						gp.setBlockSize(240);
					}
					if (args.has(OPT_INFO) || args.has(OPT_VERBOSE)) {
						System.out.println("Reader: " + reader.getName());
						System.out.println("ATR: " + HexUtils.encodeHexString(card.getATR().getBytes()));
						System.out.println("More information about your card:");
						System.out.println("    http://smartcard-atr.appspot.com/parse?ATR="+HexUtils.encodeHexString(card.getATR().getBytes()));
						System.out.println();
					}
					
					// Send all raw APDU-s to the default-selected application of the card
					if (args.has(OPT_APDU)) {
						for (Object s: args.valuesOf(OPT_APDU)) {
							CommandAPDU c = new CommandAPDU(HexUtils.stringToBin((String)s));
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
					
					// List all terminal names
					if (args.has(CMD_READERS)) {
						System.out.println(reader.getName());
					}
					
					// Authenticate, only if needed
					if (needsAuthentication(args)) {
						
						EnumSet<APDUMode> mode = GlobalPlatform.defaultMode.clone();
						// Override default mode if needed.
						if (args.has(OPT_MODE)) {
							mode.clear();
							mode.add((GlobalPlatform.APDUMode) args.valueOf(OPT_MODE));
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
								CommandAPDU c = new CommandAPDU(HexUtils.stringToBin((String)s));
								gp.transmit(c);
							}
						}
						
						// --delete <aid> or --delete --default
						if (args.has(OPT_DELETE)) {
							if (args.has(OPT_DEFAULT)) {
								gp.uninstallDefaultSelected(args.has(OPT_DELETEDEPS));
							}
							@SuppressWarnings("unchecked")
							List<AID> aids = (List<AID>) args.valuesOf(OPT_DELETE);
							for (AID aid: aids) {
								try {
									gp.deleteAID(aid, args.has(OPT_DELETEDEPS));
								} catch (GPException e) {
									if (!gp.getRegistry().allAIDs().contains(aid)) {
										System.out.println("Could not delete AID (not present on card): " + aid);
									} else {
										System.out.println("Could not delete AID: " + aid);
										if (e.sw == 0x6985) {
											System.out.println("TIP: Maybe try with --" + OPT_DELETEDEPS);
										}
										throw e;
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
						if (args.has(OPT_INSTALL) || args.hasArgument(OPT_REINSTALL)) {
							final File capfile;
							
							// Sanity check
							if (args.hasArgument(OPT_REINSTALL) && args.has(OPT_INSTALL)) {
								throw new IllegalArgumentException("Can't specify an argument for --reinstall if --install is present");
							} else if (args.hasArgument(OPT_REINSTALL)) {
								capfile = (File) args.valueOf(OPT_REINSTALL);
							} else {
								capfile = (File) args.valueOf(OPT_INSTALL);
							}
							
							CapFile instcap = new CapFile(new FileInputStream(capfile));
							
							if (args.has(OPT_VERBOSE)) {
								instcap.dump(System.out);
							}
							
							if (args.has(OPT_REINSTALL)) {
								System.err.println("Removing existing package");
								try {
									gp.deleteAID(instcap.getPackageAID(), true);
								} catch (GPException e) {
									if (e.sw == 0x6A88) {
										System.err.println("Applet with default AID-s not present on card. Ignoring.");
									} else {
										throw e;
									}
								}
							}
							
							try {
								gp.loadCapFile(instcap);
							} catch (GPException e) {
								if (e.sw == 0x6985 || e.sw == 0x6A80) {
									System.err.println("Applet loading failed. Are you sure the CAP file (JC version, packages) is compatible with your card?");
								}
								throw e;
							}
							System.err.println("CAP loaded");
							
							// Only install if cap contains a single applet
							if (instcap.getAppletAIDs().size() > 1) {
								System.out.println("CAP contains more than one applet, create instances manually with --" + OPT_CREATE);
							} else {
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
								gp.installAndMakeSelectable(instcap.getPackageAID(), appaid, null, getInstPrivs(args), getInstParams(args), null);
							}
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
							for (AIDRegistryEntry e : gp.getRegistry()) {
								AID aid = e.getAID();
								System.out.println("AID: " + HexUtils.encodeHexString(aid.getBytes()) + " (" + GPUtils.byteArrayToReadableString(aid.getBytes()) + ")");
								System.out.println("     " + e.getKind().toShortString() + " " + e.getLifeCycleString() + ": " + e.getPrivilegesString());
								
								for (AID a : e.getExecutableAIDs()) {
									System.out.println("     " + HexUtils.encodeHexString(a.getBytes()) + " (" + GPUtils.byteArrayToReadableString(a.getBytes()) + ")");
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
							if (args.has(OPT_MAC) || args.has(OPT_ENC) || args.has(OPT_KEK) && !args.has(OPT_RELAX))
								gp.giveStrictWarning("Using --" + OPT_LOCK + " but specifying other keys");
							
							// XXX: this is ugly, we re-use ArgParser only to get diverification method
							PlaintextKeys newkey = (PlaintextKeys) args.valueOf(OPT_LOCK);
							
							GPKeySet newkeys = new GPKeySet(newkey.master);
							// Diversify if requested.
							if (newkey.diversifier != Diversification.NONE) {
								newkeys = PlaintextKeys.diversify(newkeys, gp.getDiversificationData(), newkey.diversifier, gp.getSCPVersion());
							}
							
							// Check that
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
					// All unhandled GP exceptions halt the program unless it is run with -relax
					if (!args.has(OPT_RELAX)) {
						e.printStackTrace();
						System.exit(1);
					}
					e.printStackTrace();
				} catch (CardException e) {
					// Card exceptions skip to the next reader, if available and allowed
					if (args.has(OPT_CONTINUE)) {
						continue;
					} else {
						e.printStackTrace();
						throw e; // No catch.
					}
				} finally {
					if (card != null) {
						card.endExclusive();
						card.disconnect(true);
					}
				}
			}
		} catch (CardException e) {
			// Sensible wrapper for the different PC/SC exceptions
			if (TerminalManager.getExceptionMessage(e) != null) {
				System.out.println("PC/SC failure: " + TerminalManager.getExceptionMessage(e));
			} else {
				throw e;
			}
		}
		System.exit(0);
	}
	private static byte getInstPrivs(OptionSet args) {
		byte privs = 0x00;
		if (args.has(OPT_DEFAULT)) {
			privs |= GPData.defaultSelectedPriv;
		}
		if (args.has(OPT_TERMINATE)) {
			privs |= GPData.cardLockPriv | GPData.cardTerminatePriv;
		}
		if (args.has(OPT_SDOMAIN)) {
			privs |= GPData.securityDomainPriv;
		}
		return privs;
	}
	
	private static byte [] getInstParams(OptionSet args) {
		byte[] params = null;
		if (args.has(OPT_PARAMS)) {
			params = HexUtils.stringToBin((String) args.valueOf(OPT_PARAMS));
			// Simple use: only application paramters without tag, prepend 0xC9
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
		if (args.hasArgument(OPT_REINSTALL) || args.has(OPT_DELETE) || args.has(OPT_CREATE))
			return true;
		if (args.has(OPT_LOCK) || args.has(OPT_UNLOCK) || args.has(OPT_MAKE_DEFAULT))
			return true;
		if (args.has(OPT_UNINSTALL) || args.has(OPT_SECURE_APDU))
			return true;
		return false;
	}
}
