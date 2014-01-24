package openkms.gpj;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Vector;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

import openkms.gpj.KeySet.KeyDiversification;
import openkms.gpj.KeySet.KeyType;


public class GPJTool {

	public static void main(String[] args) throws Exception {

		final class InstallEntry {
			AID appletAID;
			AID packageAID;
			int priv;
			byte[] params;
		}

		boolean listApplets = false;
		int keyID = 0;
		int keyVersion = 0;
		KeySet ks = new KeySet(GlobalPlatform.defaultKey);
		AID sdAID = null;
		AID defaultAID = null;

		Vector<AID> deleteAID = new Vector<AID>();
		boolean deleteDeps = false;
		boolean deleteDefault = false;

		URL capFileUrl = null;
		int loadSize = GlobalPlatform.defaultLoadSize;

		boolean loadCompSep = false;
		boolean loadDebug = false;
		boolean loadParam = false;
		boolean useHash = false;

		boolean verbose = false;
		boolean debug = false;
		boolean relax = false;

		boolean format = false;
		boolean listReaders = false;
		boolean showInfo = false;

		int apduMode = GlobalPlatform.APDU_MAC;

		Vector<InstallEntry> installs = new Vector<InstallEntry>();

		try {
			for (int i = 0; i < args.length; i++) {

				if (args[i].equals("-h") || args[i].equals("-help") || args[i].equals("--help")) {
					usage();
					System.exit(0);
				}

				// All other options.
				if (args[i].equals("-v") || args[i].equals("-verbose")) {
					verbose = true;
				} else if (args[i].equals("-debug")) {
					debug = true;
				} else if (args[i].equals("-relax")) {
					relax = true;
				} else if (args[i].equals("-readers")) {
					listReaders = true;
				} else if (args[i].equals("-list")) {
					listApplets = true;
				} else if (args[i].equals("-info")) {
					showInfo = true;
				} else if (args[i].equals("-keyver")) {
					i++;
					keyVersion = Integer.parseInt(args[i]);
					if ((keyVersion <= 0) || (keyVersion > 127)) {
						throw new IllegalArgumentException("Key version " + keyVersion + " out of range.");
					}
				} else if (args[i].equals("-keyid")) {
					i++;
					keyID = Integer.parseInt(args[i]);
					if ((keyID <= 0) || (keyID > 127)) {
						throw new IllegalArgumentException("Key ID " + keyID + " out of range.");
					}
				} else if (args[i].equals("-sdaid")) {
					i++;
					byte[] aid = GPUtils.stringToByteArray(args[i]);
					if (aid == null) {
						throw new IllegalArgumentException("Malformed SD AID: " + args[i]);
					}
					sdAID = new AID(aid);
				} else if (args[i].equals("-default")) {
					i++;
					byte[] aid = GPUtils.stringToByteArray(args[i]);
					if (aid == null) {
						throw new IllegalArgumentException("Malformed AID: " + args[i]);
					}
					defaultAID = new AID(aid);
				} else if (args[i].equals("-visa2")) {
					ks.diversification = KeyDiversification.VISA2;
					apduMode = GlobalPlatform.APDU_MAC;
				} else if (args[i].equals("-emv")) {
					ks.diversification = KeyDiversification.EMV;
					apduMode = GlobalPlatform.APDU_MAC;
				} else if (args[i].equals("-mode")) {
					i++;
					// TODO: RMAC modes
					if ("CLR".equalsIgnoreCase(args[i])) {
						apduMode = GlobalPlatform.APDU_CLR;
					} else if ("MAC".equalsIgnoreCase(args[i])) {
						apduMode = GlobalPlatform.APDU_MAC;
					} else if ("ENC".equalsIgnoreCase(args[i])) {
						apduMode = GlobalPlatform.APDU_ENC;
					} else {
						throw new IllegalArgumentException("Invalid APDU mode: " + args[i]);
					}
				} else if (args[i].equals("-delete")) {
					i++;
					if (args[i].equals("-default")) {
						deleteDefault = true;
					} else {
						byte[] aid = GPUtils.stringToByteArray(args[i]);
						if (aid == null) {
							throw new IllegalArgumentException("Malformed AID: " + args[i]);
						}
						deleteAID.add(new AID(aid));
					}
				} else if (args[i].equals("-deletedeps")) {
					deleteDeps = true;
				} else if (args[i].equals("-format")) {
					format = true;
				} else if (args[i].equals("-loadsize")) {
					i++;
					loadSize = Integer.parseInt(args[i]);
					if ((loadSize <= 16) || (loadSize > 255)) {
						throw new IllegalArgumentException("Load size " + loadSize + " out of range.");
					}
				} else if (args[i].equals("-loadsep")) {
					loadCompSep = true;
				} else if (args[i].equals("-loaddebug")) {
					loadDebug = true;
				} else if (args[i].equals("-loadparam")) {
					loadParam = true;
				} else if (args[i].equals("-loadhash")) {
					useHash = true;
				} else if (args[i].equals("-load")) {
					i++;
					try {
						capFileUrl = new URL(args[i]);
					} catch (MalformedURLException e) {
						// Try with "file:" prepended
						capFileUrl = new URL("file:" + args[i]);
					}
					try {
						InputStream in = capFileUrl.openStream();
						in.close();
					} catch (IOException ioe) {
						throw new IllegalArgumentException("CAP file " + capFileUrl + " does not seem to exist.", ioe);
					}
				} else if (args[i].equals("-install")) {
					i++;
					int totalOpts = 5;
					int current = 0;
					AID appletAID = null;
					AID packageAID = null;
					int priv = 0;
					byte[] param = null;
					while ((i < args.length) && (current < totalOpts)) {
						if (args[i].equals("-applet")) {
							i++;
							byte[] aid = GPUtils.stringToByteArray(args[i]);
							i++;
							if (aid == null) {
								throw new IllegalArgumentException("Malformed AID: " + args[i]);
							}
							appletAID = new AID(aid);
							current = 1;
						} else if (args[i].equals("-package")) {
							i++;
							byte[] aid = GPUtils.stringToByteArray(args[i]);
							i++;
							if (aid == null) {
								throw new IllegalArgumentException("Malformed AID: " + args[i]);
							}
							packageAID = new AID(aid);
							current = 2;
						} else if (args[i].equals("-priv")) {
							i++;
							priv = Integer.parseInt(args[i]);
							i++;
							current = 3;
						} else if (args[i].equals("-default")) {
							i++;
							priv|= 0x4;
							current = 4;
						} else if (args[i].equals("-param")) {
							i++;
							param = GPUtils.stringToByteArray(args[i]);
							i++;
							if (param == null) {
								throw new IllegalArgumentException("Malformed params: " + args[i]);
							}
							current = 5;
						} else {
							current = 5;
							i--;
						}
					}
					InstallEntry inst = new InstallEntry();
					inst.appletAID = appletAID;
					inst.packageAID = packageAID;
					inst.priv = priv;
					inst.params = param;
					installs.add(inst);
				} else {
					KeyType type = null;
					for (KeyType k: KeyType.values()) {
						if (args[i].substring(1).equalsIgnoreCase(k.toString())) {
							type = k;
							break;
						}
					}
					if (type == null) {
						throw new IllegalArgumentException("Unknown parameter " + args[i]);
					} else {
						i++;
						ks.setKey(type, GPUtils.stringToByteArray(args[i]));
					}
				}
			}
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			usage();
			System.exit(1);
		}

		// Do the actual work
		try {
			TerminalFactory tf = TerminalManager.getTerminalFactory();

			if (debug)
				System.out.println("Using PC/SC provier: " + tf.getProvider().getName());

			CardTerminals terminals = tf.terminals();
			List<CardTerminal> terms = terminals.list();

			// list readers in debug mode and with -readers
			if (debug || listReaders) {
				System.out.println("# Detected readers");
				for (CardTerminal term : terms) {
					System.out.println(term.getName() + (term.isCardPresent() ? "  CARD" : " EMPTY"));
				}
				System.out.println();
			}


			// Do what is needed, connecting to all terminals with a reader
			for (CardTerminal terminal : terminals.list(CardTerminals.State.CARD_PRESENT)) {
				Card c = null;
				try {
					// Wrap the terminal with a logging wrapper if needed.
					if (debug) {
						terminal = LoggingCardTerminal.getInstance(terminal);
					}

					try {
						c = terminal.connect("*");
					} catch (CardException e) {
						if (e.getCause().getMessage().equalsIgnoreCase("SCARD_E_NO_SMARTCARD")) {
							System.err.println("No card in reader \"" + terminal.getName() + "\": " + e.getCause().getMessage());
							continue;
						} else if (e.getCause().getMessage().equalsIgnoreCase("SCARD_W_UNPOWERED_CARD")) {
							System.err.println("No card in reader \"" + terminal.getName() + "\": " + e.getCause().getMessage());
							System.err.println("  TIP: Make sure that the card is properly inserted and the chip is clean!");
							continue;
						} else {
							System.err.println("Could not read card in " + terminal.getName());
							e.printStackTrace();
							continue;
						}
					}

					if (verbose || showInfo) {
						System.out.println("Found card in reader: " + terminal.getName());
						System.out.println("ATR: " + GPUtils.byteArrayToString(c.getATR().getBytes()));
					}

					GlobalPlatform service = new GlobalPlatform(c.getBasicChannel());

					if (showInfo) {
						// Print CPLC
						System.out.println("CPLC: ");
						GlobalPlatformData.print_cplc_data(service.getCPLC());

					}

					service.setVerbose(verbose);
					service.setStrict(!relax);

					// Select sdAID
					service.select(sdAID);

					// TODO: make the APDU mode a parameter, properly adjust
					// loadSize accordingly
					int neededExtraSize = apduMode == GlobalPlatform.APDU_CLR ? 0 : (apduMode == GlobalPlatform.APDU_MAC ? 8 : 16);
					if ((loadSize + neededExtraSize) > GlobalPlatform.defaultLoadSize) {
						loadSize -= neededExtraSize;
					}
					service.openSecureChannel(ks, GlobalPlatform.SCP_ANY, apduMode);

					AIDRegistry registry = service.getStatus();

					if (deleteAID.size() > 0) {
						for (AID aid : deleteAID) {
							try {
								service.deleteAID(aid, deleteDeps);
							} catch (GPException gpe) {
								if (!registry.entries.contains(aid)) {
									System.out.println("Could not delete AID (not present on card): " + aid);
								} else {
									System.out.println("Could not delete AID: " + aid);
									gpe.printStackTrace();
								}
							}
						}
					} else if (format) {
						for (AIDRegistryEntry entry : registry.allApplets()) {
							try {
								service.deleteAID(entry.getAID(), true);
							} catch (GPException e) {
								System.out.println("Could not delete AID when formatting: " + entry.getAID() + " : 0x" + Integer.toHexString(e.sw));
							}
						}
					} else if (deleteDefault) {
						AID  aid = registry.getDefaultSelectedPackageAID();
						if (aid != null) {
							try {
								service.deleteAID(aid, true);
							} catch (GPException e) {
								System.out.println("Could not delete default applet: " + aid + " : 0x" + Integer.toHexString(e.sw));
							}
						} else {
							System.out.println("Card has no DefaultSelected applet");
						}
					}

					CapFile cap = null;

					if (capFileUrl != null) {
						cap = new CapFile(capFileUrl.openStream());
						service.loadCapFile(cap, loadDebug, loadCompSep, loadSize, loadParam, useHash);
					}

					if (installs.size() > 0) {
						for (InstallEntry install : installs) {
							if (install.appletAID == null) {
								AID p = cap.getPackageAID();
								for (AID a : cap.getAppletAIDs()) {
									service.installAndMakeSelecatable(p, a, null, (byte) install.priv, install.params, null);
								}
							} else {
								service.installAndMakeSelecatable(install.packageAID, install.appletAID, null, (byte) install.priv,
										install.params, null);

							}
						}

					}

					if (defaultAID != null)
						service.makeDefaultSelected(defaultAID, (byte) 0x04);

					if (listApplets) {
						registry = service.getStatus();
						for (AIDRegistryEntry e : registry) {
							AID aid = e.getAID();
							System.out.println("AID: " + GPUtils.byteArrayToString(aid.getBytes()) + " (" + GPUtils.byteArrayToReadableString(aid.getBytes()) + ")");
							System.out.println("     " + e.getKind().toShortString() + " " + e.getLifeCycleString() + ": " + e.getPrivilegesString());

							for (AID a : e.getExecutableAIDs()) {
								System.out.println("     " + GPUtils.byteArrayToString(a.getBytes()) + " (" + GPUtils.byteArrayToReadableString(a.getBytes()) + ")");
							}
							System.out.println();
						}
					}
				} finally {
					if (c != null) {
						TerminalManager.disconnect(c, true);
					}
				}
			}
		} catch (CardException e) {
			e.printStackTrace();
			if (e.getCause().getMessage().equalsIgnoreCase("SCARD_E_NO_READERS_AVAILABLE")) {
				System.out.println("No smart card readers found (No readers available)");
			} else {
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			if (e.getCause().getMessage().equalsIgnoreCase("SCARD_E_NO_SERVICE")) {
				System.out.println("No smart card readers found (PC/SC service not running)");
			} else {
				e.printStackTrace();
			}
		} catch (Exception e) {
			System.out.println("Terminated by escaping exception: " + e.getClass().getName());
			e.printStackTrace();
			System.exit(1);
		}

	}

	public static void usage() {
		System.out.println("Usage:");
		System.out.println("  java -jar openkms-globalplatform.jar <options>");
		System.out.println("");
		System.out.println("Options:");
		System.out.println(" -debug            print APDU-s exchanged with the card");
		System.out.println(" -verbose          print more information about card and ");
		System.out.println(" -readers          print all found card raders");
		System.out.println(" -relax            relax checks (lockup warning!)");
		System.out.println(" -info             show interesting information about cards");
		System.out.println(" -sdaid <aid>      security Domain AID (default: auto-detect)");
		System.out.println(" -keyver <num>     use key version <num> (default: 0)");
		System.out.println(" -keyid <num>      use key ID <num> (default: 0)");
		System.out.println(" -mode <apduMode>  use APDU mode, CLR, MAC, or ENC (default: MAC)");
		System.out.println(" -enc <key>        define ENC key (default: 40..4F)");
		System.out.println(" -mac <key>        define MAC key (default: 40..4F)");
		System.out.println(" -kek <key>        define KEK key (default: 40..4F)");
		System.out.println(" -visa2            use VISA2 key diversification (only key version 0), default off");
		System.out.println(" -emv              use EMV key diversification (only key version 0), default off");
		System.out.println(" -deletedeps       also delete depending packages/applets, default off");
		System.out.println(" -delete <aid>     delete package/applet");
		System.out.println(" -format           format the card (try to delete all content)");
		System.out.println(" -load <cap>       load <cap> file to the card, <cap> can be file name or URL");
		System.out.println(" -loadsize <num>   load block size, default " + GlobalPlatform.defaultLoadSize);
		System.out.println(" -loadsep          load CAP components separately, default off");
		System.out.println(" -loaddebug        load the Debug & Descriptor component, default off");
		System.out.println(" -loadparam        set install for load code size parameter");
		System.out.println("                      (e.g. for CyberFlex cards), default off");
		System.out.println(" -loadhash         check code hash during loading");
		System.out.println(" -install          install applet:");
		System.out.println("   -applet <aid>   applet AID, default: take all AIDs from the CAP file");
		System.out.println("   -package <aid>  package AID, default: take from the CAP file");
		System.out.println("   -priv <num>     privileges, default 0");
		System.out.println("   -param <bytes>  install parameters, default: C900");
		System.out.println(" -default <aid>    make the specified AID default selected");

		System.out.println(" -list             list card registry");
		System.out.println(" -h|-help|--help   print this usage info");
		System.out.println("");
		System.out.println("Multiple -load/-install/-delete and -list take the following precedence:");
		System.out.println("  delete(s), load, install(s), list");
		System.out.println("");
		System.out.println("All -load/-install/-delete/-list actions will be performed on");
		System.out.println("the basic logical channel of all cards currently connected.");
		System.out.println("By default all connected PC/SC readers are searched.");
		System.out.println("");
		System.out.println("Examples:");
		System.out.println("");
		System.out.println("  [prog] -list");
		System.out.println("  [prog] -load applet.cap -install -list");
		System.out.println("  [prog] -deletedeps -delete 360000000001 -load applet.cap -install -list");
		System.out.println("  [prog] -emv -keyset 0 -enc 404142434445464748494A4B4C4D4E4F -list");
		System.out.println("");
	}
}
