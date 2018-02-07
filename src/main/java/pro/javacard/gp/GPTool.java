/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2017 Martin Paljak, martin@martinpaljak.net
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
import pro.javacard.gp.GPKey.Type;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPRegistryEntry.Privileges;
import pro.javacard.gp.GlobalPlatform.APDUMode;
import pro.javacard.gp.GlobalPlatform.GPSpec;

import javax.crypto.Cipher;
import javax.smartcardio.*;
import javax.smartcardio.CardTerminals.State;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Collectors;

import static pro.javacard.gp.PlaintextKeys.Diversification.EMV;
import static pro.javacard.gp.PlaintextKeys.Diversification.VISA2;

public final class GPTool {
    private final static String OPT_APDU = "apdu";
    private final static String OPT_APPLET = "applet"; // can always be shortened, so -app is valid
    private final static String OPT_BS = "bs";
    private final static String OPT_CAP = "cap";
    private final static String OPT_CREATE = "create";
    private final static String OPT_DEBUG = "debug";
    private final static String OPT_DEFAULT = "default";
    private final static String OPT_DELETE = "delete";
    private final static String OPT_DELETE_KEY = "delete-key";

    private final static String OPT_DOMAIN = "domain";
    private final static String OPT_DUMP = "dump";
    private final static String OPT_EMV = "emv";
    private final static String OPT_FORCE = "force";
    private final static String OPT_INFO = "info";
    private final static String OPT_INITIALIZED = "initialized";
    private final static String OPT_INSTALL = "install";
    private final static String OPT_KCV = "kcv";
    private final static String OPT_KEY = "key";
    private final static String OPT_KEYS = "keys";
    private final static String OPT_KEY_ENC = "key-enc";
    private final static String OPT_KEY_ID = "key-id";
    private final static String OPT_KEY_DEK = "key-dek";
    private final static String OPT_KEY_MAC = "key-mac";
    private final static String OPT_KEY_VERSION = "key-ver";
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
    private final static String OPT_PRIVS = "privs";
    private final static String OPT_PUT_KEY = "put-key";

    private final static String OPT_READER = "reader";
    private final static String OPT_RENAME_ISD = "rename-isd";
    private final static String OPT_REPLAY = "replay";
    private final static String OPT_SC_MODE = "mode";
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
    private final static String OPT_VISA2 = "visa2";
    private final static String OPT_ORACLE = "oracle";

    private final static String OPT_ACR_LIST = "acr-list";
    private final static String OPT_ACR_ADD = "acr-add";
    private final static String OPT_ACR_DELETE = "acr-delete";
    private final static String OPT_ACR_RULE = "acr-rule";
    private final static String OPT_ACR_CERT_HASH = "acr-hash";

    private static OptionSet parseArguments(String[] argv) throws IOException {
        OptionSet args = null;
        OptionParser parser = new OptionParser();

        // Generic options
        parser.acceptsAll(Arrays.asList("V", OPT_VERSION), "Show information about the program");
        parser.acceptsAll(Arrays.asList("h", "?", "help"), "Shows this help string").forHelp();
        parser.acceptsAll(Arrays.asList("d", OPT_DEBUG), "Show PC/SC and APDU trace");
        parser.acceptsAll(Arrays.asList("v", OPT_VERBOSE), "Be verbose about operations");
        parser.acceptsAll(Arrays.asList("r", OPT_READER), "Use specific reader").withRequiredArg();
        parser.acceptsAll(Arrays.asList("l", OPT_LIST), "List the contents of the card");
        parser.acceptsAll(Arrays.asList("i", OPT_INFO), "Show information");
        parser.acceptsAll(Arrays.asList("a", OPT_APDU), "Send raw APDU (hex)").withRequiredArg().describedAs("APDU");
        parser.acceptsAll(Arrays.asList("s", OPT_SECURE_APDU), "Send raw APDU (hex) via SCP").withRequiredArg().describedAs("APDU");
        parser.acceptsAll(Arrays.asList("f", OPT_FORCE), "Force operation");
        parser.accepts(OPT_DUMP, "Dump APDU communication to <File>").withRequiredArg().ofType(File.class);
        parser.accepts(OPT_REPLAY, "Replay APDU responses from <File>").withRequiredArg().ofType(File.class);

        // Special options
        parser.accepts(OPT_TERMINALS, "Use PC/SC provider from <jar:class>").withRequiredArg();

        // Applet operation options
        parser.accepts(OPT_CAP, "Use a CAP file as source").withRequiredArg().ofType(File.class);
        parser.accepts(OPT_LOAD, "Load a CAP file").withRequiredArg().ofType(File.class);

        parser.accepts(OPT_INSTALL, "Install applet(s) from CAP").withOptionalArg().ofType(File.class);
        parser.accepts(OPT_PARAMS, "Installation parameters").withRequiredArg().describedAs("HEX");
        parser.accepts(OPT_PRIVS, "Specify privileges for installation").withRequiredArg();
        parser.accepts(OPT_LIST_PRIVS, "List known privileges");

        parser.accepts(OPT_UNINSTALL, "Uninstall applet/package").withRequiredArg().ofType(File.class);
        parser.accepts(OPT_DEFAULT, "Indicate Default Selected privilege");
        parser.accepts(OPT_TERMINATE, "Indicate Card Lock+Terminate privilege");
        parser.accepts(OPT_DOMAIN, "Create supplementary security domain").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_LOCK_APPLET, "Lock applet").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_UNLOCK_APPLET, "Unlock applet").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_LOCK_CARD, "Lock card");
        parser.accepts(OPT_UNLOCK_CARD, "Unlock card");
        parser.accepts(OPT_SECURED, "Transition ISD to SECURED state");
        parser.accepts(OPT_INITIALIZED, "Transition ISD to INITIALIZED state");
        parser.accepts(OPT_STORE_DATA, "STORE DATA to applet").withRequiredArg().describedAs("data");

        parser.accepts(OPT_MAKE_DEFAULT, "Make AID the default").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_RENAME_ISD, "Rename ISD").withRequiredArg().describedAs("new AID");

        parser.accepts(OPT_DELETE, "Delete applet/package").withOptionalArg().describedAs("AID");
        parser.accepts(OPT_DELETE_KEY, "Delete key with version").withRequiredArg();

        parser.accepts(OPT_CREATE, "Create new instance of an applet").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_APPLET, "Applet AID").withRequiredArg().describedAs("AID");
        parser.acceptsAll(Arrays.asList(OPT_PACKAGE, "pkg"), "Package AID").withRequiredArg().describedAs("AID");

        // Key options
        parser.accepts(OPT_KEY, "Specify master key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_KCV, "Specify master key check value").withRequiredArg().describedAs("KCV");

        parser.accepts(OPT_KEY_MAC, "Specify card MAC key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_KEY_ENC, "Specify card ENC key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_KEY_DEK, "Specify card DEK key").withRequiredArg().describedAs("key");

        parser.accepts(OPT_EMV, "Use EMV diversification");
        parser.accepts(OPT_VISA2, "Use VISA2 diversification");

        parser.accepts(OPT_ORACLE, "Use an oracle for keying information").withOptionalArg().describedAs("URL");

        parser.accepts(OPT_KEY_ID, "Specify key ID").withRequiredArg();
        parser.accepts(OPT_KEY_VERSION, "Specify key version").withRequiredArg();
        parser.accepts(OPT_PUT_KEY, "Put a new key").withRequiredArg();

        parser.accepts(OPT_LOCK, "Set new key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_UNLOCK, "Set default key for card key");
        parser.accepts(OPT_NEW_KEY_VERSION, "Key version for the new key").withRequiredArg();

        // access rules
        parser.accepts(OPT_ACR_LIST, "List access rules");
        parser.accepts(OPT_ACR_ADD, "Add an access rule");
        parser.accepts(OPT_ACR_DELETE, "Delete an access rule");
        parser.accepts(OPT_ACR_RULE, "Access control rule (can be 0x00(NEVER),0x01(ALWAYS) or an apdu filter").withRequiredArg();
        parser.accepts(OPT_ACR_CERT_HASH, "Certificate hash (sha1)").withRequiredArg();

        // General GP options
        parser.accepts(OPT_SC_MODE, "Secure channel to use (mac/enc/clr)").withRequiredArg();
        parser.accepts(OPT_BS, "maximum APDU payload size").withRequiredArg().ofType(Integer.class);
        parser.accepts(OPT_OP201, "Enable OpenPlatform 2.0.1 mode");

        parser.accepts(OPT_SDAID, "ISD AID").withRequiredArg().describedAs("AID");

        // Parse arguments
        try {
            args = parser.parse(argv);
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

        if (args.has("help")) {
            parser.printHelpOn(System.out);
            System.exit(0);
        }

        return args;
    }

    public static void main(String[] argv) throws Exception {
        OptionSet args = parseArguments(argv);

        // Set up slf4j simple in a way that pleases us
        System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
        System.setProperty("org.slf4j.simpleLogger.levelInBrackets", "true");
        System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");

        if (args.has(OPT_VERBOSE)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        } else if (args.has(OPT_DEBUG)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
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

        // Load a CAP file, if specified
        CAPFile cap = null;
        if (args.has(OPT_CAP)) {
            File capfile = (File) args.valueOf(OPT_CAP);
            cap = new CAPFile(new FileInputStream(capfile));
            if (args.has(OPT_INFO)) {
                System.out.println("**** CAP info of " + capfile.getName());
                cap.dump(System.out);
            }
        }

        if (args.has(OPT_LIST_PRIVS)) {
            System.out.println("# Known privileges:");
            System.out.println(Arrays.asList(Privilege.values()).stream().map(i -> i.toString()).collect(Collectors.joining("\n")));
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
                tf = TerminalManager.getTerminalFactory((String) args.valueOf(OPT_TERMINALS));
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
            for (CardTerminal reader : do_readers) {
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

                    if (args.has(OPT_INFO) || args.has(OPT_VERBOSE)) {
                        System.out.println("Reader: " + reader.getName());
                        System.out.println("ATR: " + HexUtils.bin2hex(card.getATR().getBytes()));
                        System.out.println("More information about your card:");
                        System.out.println("    http://smartcard-atr.appspot.com/parse?ATR=" + HexUtils.bin2hex(card.getATR().getBytes()));
                        System.out.println();
                    }

                    // Send all raw APDU-s to the default-selected application of the card
                    if (args.has(OPT_APDU)) {
                        for (Object s : args.valuesOf(OPT_APDU)) {
                            CommandAPDU c = new CommandAPDU(HexUtils.stringToBin((String) s));
                            card.getBasicChannel().transmit(c);
                        }
                    }

                    // GlobalPlatform specific
                    final GlobalPlatform gp;
                    if (args.has(OPT_SDAID)) {
                        gp = GlobalPlatform.connect(card.getBasicChannel(), AID.fromString(args.valueOf(OPT_SDAID)));
                    } else {
                        // Oracle only applies if no other arguments given
                        gp = GlobalPlatform.discover(card.getBasicChannel());
                        // FIXME: would like to get AID from oracle as well.
                    }

                    // Normally assume a single master key
                    final GPSessionKeyProvider keys;

                    if (args.has(OPT_KEYS)) {
                        // keys come from custom provider
                        fail("Not yet implemented");
                        keys = PlaintextKeys.fromMasterKey(GPData.getDefaultKey());
                    } else if (args.has(OPT_ORACLE)) {
                        keys = PythiaKeys.ask(card.getATR().getBytes(), gp.fetchCPLC(), gp.getKeyInfoTemplateBytes());
                    } else {
                        PlaintextKeys keyz;
                        if (args.has(OPT_KEY)) {
                            GPKey k = new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_KEY)));
                            if (args.has(OPT_KCV)) {
                                byte[] given = HexUtils.stringToBin((String) args.valueOf(OPT_KCV));
                                byte[] expected = k.getKCV();
                                if (expected.length == 0) {
                                    fail("Don't know how to calculate KCV for the key"); // FIXME: all keys are RAW currently
                                }
                                // Check KCV
                                if (!Arrays.equals(given, expected)) {
                                    fail("KCV does not match, expected " + HexUtils.bin2hex(expected) + " but given " + HexUtils.bin2hex(given));
                                }
                            }
                            keyz = PlaintextKeys.fromMasterKey(k);
                        } else {
                            // XXX: better checks for exclusive key options
                            if (args.has(OPT_KEY_MAC) && args.has(OPT_KEY_ENC) && args.has(OPT_KEY_DEK)) {
                                GPKey enc = new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_KEY_ENC)));
                                GPKey mac = new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_KEY_MAC)));
                                GPKey dek = new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_KEY_DEK)));
                                keyz = PlaintextKeys.fromKeys(enc, mac, dek);
                            } else {
                                System.out.println("Warning: no keys given, using default test key " + HexUtils.bin2hex(GPData.defaultKeyBytes));
                                keyz = PlaintextKeys.fromMasterKey(GPData.getDefaultKey());
                            }
                        }

                        // "gp -l -emv" should still work
                        if (args.has(OPT_VISA2)) {
                            keyz.setDiversifier(VISA2);
                        } else if (args.has(OPT_EMV)) {
                            keyz.setDiversifier(EMV);
                        }

                        if (args.has(OPT_KEY_VERSION)) {
                            keyz.setVersion(GPUtils.intValue((String) args.valueOf(OPT_KEY_VERSION)));
                        }
                        keys = keyz;
                    }

                    // XXX: leftover
                    if (args.has(OPT_OP201)) {
                        gp.setSpec(GPSpec.OP201);
                    }

                    // Override block size for stupidly broken readers.
                    // See https://github.com/martinpaljak/GlobalPlatformPro/issues/32
                    // The name of the option comes from a common abbreviation as well as dd utility
                    if (args.has(OPT_BS)) {
                        gp.setBlockSize((int) args.valueOf(OPT_BS));
                    }

                    // list access rules
                    if (args.has(OPT_ACR_LIST)) {
                        SEAccessControlUtility.acrList(gp, card);
                    }

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
                            mode.add(APDUMode.fromString((String) args.valueOf(OPT_SC_MODE)));
                        }

                        // Possibly brick the card now, if keys don't match.
                        gp.openSecureChannel(keys, null, 0, mode);

                        // --secure-apdu or -s
                        if (args.has(OPT_SECURE_APDU)) {
                            for (Object s : args.valuesOf(OPT_SECURE_APDU)) {
                                CommandAPDU c = new CommandAPDU(HexUtils.stringToBin((String) s));
                                gp.transmit(c);
                            }
                        }

                        // --delete <aid> or --delete --default
                        if (args.has(OPT_DELETE)) {
                            GPRegistry reg = gp.getRegistry();

                            // DWIM: assume that default selected is the one to be deleted
                            if (args.has(OPT_DEFAULT) && reg.getDefaultSelectedAID() != null) {
                                if (reg.getDefaultSelectedPackageAID() != null) {
                                    gp.deleteAID(reg.getDefaultSelectedPackageAID(), true);
                                } else {
                                    System.err.println("Could not identify default selected application!");
                                }
                            }
                            @SuppressWarnings("unchecked")
                            List<String> aids = (List<String>) args.valuesOf(OPT_DELETE);

                            for (String s : aids) {
                                AID aid = AID.fromString(s);
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
                            CAPFile instcap = new CAPFile(new FileInputStream(capfile));
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
                            CAPFile loadcap = new CAPFile(new FileInputStream(capfile));

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


                        // --install <applet.cap> (--applet <aid> --create <aid> --privs <privs> --params <params>)
                        if (args.has(OPT_INSTALL)) {
                            final File capfile;
                            capfile = (File) args.valueOf(OPT_INSTALL);

                            CAPFile instcap = new CAPFile(new FileInputStream(capfile));

                            if (args.has(OPT_VERBOSE)) {
                                instcap.dump(System.out);
                            }
                            // Only install if cap contains a single applet
                            if (instcap.getAppletAIDs().size() == 0) {
                                fail("No applets in CAP, use --" + OPT_LOAD + " instead");
                                // TODO: DWIM: why not load with --install
                            }

                            final AID appaid;
                            final AID instanceaid;
                            if (instcap.getAppletAIDs().size() > 1) {
                                if (args.has(OPT_APPLET)) {
                                    appaid = AID.fromString(args.valueOf(OPT_APPLET));
                                } else {
                                    fail("CAP contains more than one applet, specify the right one with --" + OPT_APPLET);
                                    return;
                                }
                            } else {
                                appaid = instcap.getAppletAIDs().get(0);
                            }

                            // override
                            if (args.has(OPT_CREATE)) {
                                instanceaid = AID.fromString(args.valueOf(OPT_CREATE));
                            } else {
                                instanceaid = appaid;
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
                                System.out.println("CAP loaded");
                            } catch (GPException e) {
                                if (e.sw == 0x6985 || e.sw == 0x6A80) {
                                    System.err.println("Applet loading failed. Are you sure the CAP file (JC version, packages) is compatible with your card?");
                                }
                                throw e;
                            }

                            // warn
                            if (gp.getRegistry().allAIDs().contains(instanceaid)) {
                                System.err.println("WARNING: Applet " + instanceaid + " already present on card");
                            }
                            // shoot
                            gp.installAndMakeSelectable(instcap.getPackageAID(), appaid, instanceaid, privs, getInstParams(args), null);
                        }

                        // --create <aid> (--applet <aid> --package <aid> or --cap <cap>)
                        if (args.has(OPT_CREATE)) {
                            AID packageAID = null;
                            AID appletAID = null;

                            // Load AID-s from cap if present
                            if (cap != null) {
                                packageAID = cap.getPackageAID();
                                if (cap.getAppletAIDs().size() != 1) {
                                    throw new IllegalArgumentException("There should be only one applet in CAP. Use --" + OPT_APPLET + " instead.");
                                }
                                appletAID = cap.getAppletAIDs().get(0);
                            }

                            // override
                            if (args.has(OPT_PACKAGE)) {
                                packageAID = AID.fromString(args.valueOf(OPT_PACKAGE));
                            }
                            if (args.has(OPT_APPLET)) {
                                appletAID = AID.fromString(args.valueOf(OPT_APPLET));
                            }

                            // check
                            if (packageAID == null || appletAID == null)
                                throw new IllegalArgumentException("Need --" + OPT_PACKAGE + " and --" + OPT_APPLET + " or --" + OPT_CAP);

                            // warn
                            if (gp.getRegistry().allAIDs().contains(appletAID)) {
                                System.err.println("WARNING: Applet " + appletAID + " already present on card");
                            }

                            // shoot
                            AID instanceAID = AID.fromString(args.valueOf(OPT_CREATE));
                            gp.installAndMakeSelectable(packageAID, appletAID, instanceAID, getInstPrivs(args), getInstParams(args), null);
                        }

                        // --domain <AID>
                        if (args.has(OPT_DOMAIN)) {
                            // Default AID-s
                            AID packageAID = new AID("A0000001515350");
                            AID appletAID = new AID("A000000151535041");

                            // Override if necessary
                            if (args.has(OPT_PACKAGE) && args.has(OPT_APPLET)) {
                                packageAID = AID.fromString(args.valueOf(OPT_PACKAGE));
                                appletAID = AID.fromString(args.valueOf(OPT_APPLET));
                            } else {
                                System.out.println("Note: using default AID-s for SSD: " + appletAID + " from " + packageAID);
                            }
                            AID instanceAID = AID.fromString(args.valueOf(OPT_DOMAIN));

                            // Extra privileges
                            Privileges privs = getInstPrivs(args);
                            privs.add(Privilege.SecurityDomain);

                            // shoot
                            gp.installAndMakeSelectable(packageAID, appletAID, instanceAID, privs, null, null);
                        }

                        // --store-data <XX>
                        if (args.has(OPT_STORE_DATA)) {
                            if (args.has(OPT_APPLET)) {
                                gp.storeData(AID.fromString(args.valueOf(OPT_APPLET)), HexUtils.stringToBin((String) args.valueOf(OPT_STORE_DATA)));
                            } else {
                                System.err.println("Must specify target application with -" + OPT_APPLET);
                            }
                        }

                        if (args.has(OPT_ACR_ADD)) {
                            if (!args.has(OPT_ACR_CERT_HASH)) {
                                System.err.println("Must specify certificate hash with -" + OPT_ACR_CERT_HASH);
                            } else if (!args.has(OPT_APPLET)) {
                                System.err.println("Must specify target application id with -" + OPT_APPLET);
                            } else if (!args.has(OPT_ACR_RULE)) {
                                System.err.println("Must specify an access rule with -" + OPT_ACR_RULE + " (00, 01 or an apdu filter)");
                            } else if (HexUtils.stringToBin((String) args.valueOf(OPT_ACR_CERT_HASH)).length == 20) {
                                SEAccessControlUtility.acrAdd(gp, AID.fromString(args.valueOf(OPT_APPLET)), HexUtils.stringToBin((String) args.valueOf(OPT_ACR_CERT_HASH)), HexUtils.stringToBin((String) args.valueOf(OPT_ACR_RULE)));
                            } else {
                                System.err.println("certificate hash must be 20 bytes");
                            }
                        }

                        if (args.has(OPT_ACR_DELETE)) {
                            if (!args.has(OPT_APPLET)) {
                                System.err.println("Must specify target application id with -" + OPT_APPLET);
                            } else if (args.has(OPT_ACR_CERT_HASH)) {
                                byte[] hash = HexUtils.stringToBin((String) args.valueOf(OPT_ACR_CERT_HASH));
                                if (hash.length == 20) {
                                    SEAccessControlUtility.acrDelete(gp, AID.fromString(args.valueOf(OPT_APPLET)), hash);
                                } else {
                                    System.err.println("certificate hash must be 20 bytes");
                                }
                            } else {
                                SEAccessControlUtility.acrDelete(gp, AID.fromString(args.valueOf(OPT_APPLET)), null);
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
                            // Skip INITIALIZED
                            GPRegistryEntryApp isd = gp.getRegistry().getISD();
                            if (isd == null) {
                                GPCommands.listRegistry(gp.getRegistry(), System.out, true);
                                fail("ISD is null");
                            }
                            if (isd.getLifeCycle() != GPData.initializedStatus) {
                                if (args.has(OPT_FORCE)) {
                                    gp.setCardStatus(GPData.initializedStatus);
                                }
                            }
                            gp.setCardStatus(GPData.securedStatus);
                        }

                        // --lock-applet <aid>
                        if (args.has(OPT_LOCK_APPLET)) {
                            gp.lockUnlockApplet(AID.fromString(args.valueOf(OPT_LOCK_APPLET)), true);
                        }

                        // --unlock-applet <AID>
                        if (args.has(OPT_UNLOCK_APPLET)) {
                            gp.lockUnlockApplet(AID.fromString(args.valueOf(OPT_UNLOCK_APPLET)), false);
                        }

                        // --list
                        if (args.has(OPT_LIST)) {
                            GPCommands.listRegistry(gp.getRegistry(), System.out, args.has(OPT_VERBOSE));
                        }

                        // --delete-key
                        // TODO: make --delete smart enough
                        if (args.has(OPT_DELETE_KEY)) {
                            int keyver = GPUtils.intValue((String) args.valueOf(OPT_DELETE_KEY));
                            System.out.println("Deleting key " + keyver);
                            gp.deleteKey(keyver);
                        }

                        // TODO: Move to GPCommands
                        // --unlock
                        if (args.has(OPT_UNLOCK)) {
                            // Write default keys
                            List<GPKey> newkeys = new ArrayList<>();
                            final boolean replace;
                            final int kv;
                            // Factory keys
                            if (gp.getScpKeyVersion() == 255) {
                                replace = false;
                                kv = 1;
                            } else {
                                // Replace current key
                                kv = gp.getScpKeyVersion();
                                replace = true;
                            }

                            // FIXME: new key must adhere to currently used SCP version.
                            GPKey new_key = new GPKey(GPData.defaultKeyBytes, gp.getSCPVersion() == 3 ? Type.AES : Type.DES3);

                            // XXX: ID handling ?
                            newkeys.add(new GPKey(kv, 1, new_key));
                            newkeys.add(new GPKey(kv, 2, new_key));
                            newkeys.add(new GPKey(kv, 3, new_key));

                            gp.putKeys(newkeys, replace);

                            System.out.println("Default " + new_key.toString() + " set as master key.");
                        }

                        // --lock
                        if (args.has(OPT_LOCK)) {
                            // By default we try to change an existing key
                            boolean replace = true;
                            List<GPKey> current = gp.getKeyInfoTemplate();

                            // By default use key version 1
                            int new_version = 1;
                            // If there are keys present, check the existing version
                            if (current.size() > 0) {
                                if (current.get(0).getVersion() == 255) {
                                    // Factory keys, add keyset with version one.
                                    replace = false;
                                } else {
                                    // Existing keys, change the present version
                                    new_version = current.get(0).getVersion();
                                }
                            }

                            // Get key value
                            GPKey nk = new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_LOCK)));
                            // XXX: this is uggely
                            if (gp.getSCPVersion() == 3)
                                nk.become(Type.AES);
                            else
                                nk.become(Type.DES3);

                            // If a specific new key version is specified, use that instead.
                            if (args.has(OPT_NEW_KEY_VERSION)) {
                                new_version = GPUtils.intValue((String) args.valueOf(OPT_NEW_KEY_VERSION));
                                System.out.println("New version: " + new_version);
                            }

                            // Add into a list
                            List<GPKey> updatekeys = new ArrayList<>();
                            // We currently use the same key, diversification is missing
                            updatekeys.add(new GPKey(new_version, 1, nk));
                            updatekeys.add(new GPKey(new_version, 2, nk));
                            updatekeys.add(new GPKey(new_version, 3, nk));

                            gp.putKeys(updatekeys, replace);

                            System.out.println("Card locked with: " + HexUtils.bin2hex(nk.getBytes()));
                            System.out.println("Write this down, DO NOT FORGET/LOSE IT!");
                        }

                        // --make-default <aid>
                        if (args.has(OPT_MAKE_DEFAULT)) {
                            gp.makeDefaultSelected(AID.fromString(args.valueOf(OPT_MAKE_DEFAULT)));
                        }

                        // --rename-isd
                        if (args.has(OPT_RENAME_ISD)) {
                            gp.renameISD(AID.fromString(args.valueOf(OPT_RENAME_ISD)));
                        }
                    }
                } catch (GPException e) {
                    //if (args.has(OPT_DEBUG)) {
                    //    e.printStackTrace(System.err);
                    // }
                    // All unhandled GP exceptions halt the program unless it is run with -force
                    if (!args.has(OPT_FORCE)) {
                        fail(e.getMessage());
                    }
                } catch (CardException e) {
                    System.out.println("Failed to communicate with card in " + reader + ": " + e.getMessage());
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
            addPrivs(privs, (String) args.valueOf(OPT_PRIVS));
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
        if (v == null)
            return privs;
        String[] parts = v.split(",");
        for (String s : parts) {
            Privilege p = Privilege.lookup(s.trim());
            if (p == null) {
                throw new IllegalArgumentException("Unknown privilege: " + s.trim());
            } else {
                privs.add(p);
            }
        }
        return privs;
    }

    private static byte[] getInstParams(OptionSet args) {
        byte[] params = null;
        if (args.has(OPT_PARAMS)) {
            String arg = (String) args.valueOf(OPT_PARAMS);
            // XXX: keep Coverity happy, even though args.has() should guard this
            if (arg == null)
                return params;
            params = HexUtils.stringToBin(arg);
            if (params == null || params.length == 0)
                return params;
            // Simple use: only application parameters without tag, prepend 0xC9
            if (params[0] != (byte) 0xC9) {
                byte[] newparams = new byte[params.length + 2];
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
        if (args.has(OPT_DELETE_KEY) || args.has(OPT_DELETE) || args.has(OPT_CREATE))
            return true;
        if (args.has(OPT_ACR_ADD) || args.has(OPT_ACR_DELETE))
            return true;
        if (args.has(OPT_LOCK) || args.has(OPT_UNLOCK) || args.has(OPT_MAKE_DEFAULT))
            return true;
        if (args.has(OPT_UNINSTALL) || args.has(OPT_SECURE_APDU) || args.has(OPT_DOMAIN))
            return true;
        if (args.has(OPT_LOCK_CARD) || args.has(OPT_UNLOCK_CARD) || args.has(OPT_LOCK_APPLET) || args.has(OPT_UNLOCK_APPLET))
            return true;
        if (args.has(OPT_STORE_DATA) || args.has(OPT_INITIALIZED) || args.has(OPT_SECURED) || args.has(OPT_RENAME_ISD))
            return true;
        return false;
    }

    private static void fail(String msg) {
        System.err.println(msg);
        System.exit(1);
    }
}
