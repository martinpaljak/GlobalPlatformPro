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

import apdu4j.*;
import joptsimple.OptionSet;
import pro.javacard.AID;
import pro.javacard.CAPFile;
import pro.javacard.gp.GPKey.Type;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPRegistryEntry.Privileges;
import pro.javacard.gp.GlobalPlatform.APDUMode;
import pro.javacard.gp.GlobalPlatform.GPSpec;

import javax.crypto.Cipher;
import javax.smartcardio.*;
import javax.smartcardio.CardTerminals.State;
import java.io.*;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static pro.javacard.gp.PlaintextKeys.Diversification.*;

public final class GPTool extends GPCommandLineInterface {

    private static boolean isVerbose = false;

    public static void main(String[] argv) throws Exception {
        OptionSet args = parseArguments(argv);

        // Set up slf4j simple in a way that pleases us
        System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
        System.setProperty("org.slf4j.simpleLogger.levelInBrackets", "true");
        System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");

        if (args.has(OPT_VERBOSE)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
            isVerbose = true;
        } else {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");
        }

        if (args.has(OPT_DEBUG)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
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
            try (FileInputStream fin = new FileInputStream(capfile)) {
                cap = CAPFile.fromStream(fin);
            }
            if (args.has(OPT_INFO)) {
                System.out.println("**** CAP info of " + capfile.getName());
                cap.dump(System.out);
                if (args.specs().size() == 2) {
                    // Exit after --cap <file> --info
                    System.exit(0);
                }
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
                try (FileInputStream fin = new FileInputStream(f)) {
                    tf = TerminalFactory.getInstance("PC/SC", fin, new APDUReplayProvider());
                }
            } else {
                tf = TerminalManager.getTerminalFactory((String) args.valueOf(OPT_TERMINALS));
            }

            CardTerminals terminals = tf.terminals();

            // List terminals if needed
            if (args.has(OPT_DEBUG)) {
                System.out.println("# Detected readers from " + tf.getProvider().getName());
                for (CardTerminal term : terminals.list()) {
                    String c = " ";
                    if (term.isCardPresent()) {
                        c = "*";
                        if (ignoreReader(term.getName())) {
                            c = "I";
                        }
                    }
                    System.out.println("[" + c + "] " + term.getName());
                }
            }

            // Select terminal(s) to work on
            List<CardTerminal> do_readers;
            if (args.has(OPT_READER) || System.getenv().containsKey("GP_READER")) {
                String reader = System.getenv("GP_READER");
                if (args.has(OPT_READER))
                    reader = (String) args.valueOf(OPT_READER);
                CardTerminal t = terminals.getTerminal(reader);
                if (t == null) {
                    fail("Reader \"" + reader + "\" not found.");
                }
                do_readers = Arrays.asList(t);
            } else {
                List<CardTerminal> tmp = terminals.list(State.CARD_PRESENT);
                do_readers = new ArrayList<>();
                for (CardTerminal t : tmp) {
                    if (!ignoreReader(t.getName())) {
                        do_readers.add(t);
                    } else {
                        if (args.has(OPT_VERBOSE)) {
                            System.out.println("# Ignoring " + t.getName());
                        }
                    }
                }
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
                CardChannel channel = null;
                try {
                    // Establish connection
                    try {
                        card = reader.connect("*");
                        // We use apdu4j which by default uses jnasmartcardio
                        // which uses real SCardBeginTransaction
                        card.beginExclusive();
                        channel = card.getBasicChannel();
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
                        // Select the application, if present
                        AID target = null;
                        if (args.has(OPT_APPLET)) {
                            target = AID.fromString(args.valueOf(OPT_APPLET));
                        } else if (cap != null) {
                            target = cap.getAppletAIDs().get(0); // FIXME: generalize and only work if one 
                        }
                        if (target != null) {
                            verbose("Selecting " + target);
                            channel.transmit(new CommandAPDU(0x00, ISO7816.INS_SELECT, 0x04, 0x00, target.getBytes()));
                        }
                        for (Object s : args.valuesOf(OPT_APDU)) {
                            CommandAPDU c = new CommandAPDU(HexUtils.stringToBin((String) s));
                            channel.transmit(c);
                        }
                    }

                    Map<String, String> env = System.getenv();

                    // GlobalPlatform specific
                    final GlobalPlatform gp;
                    if (args.has(OPT_SDAID)) {
                        gp = GlobalPlatform.connect(channel, AID.fromString(args.valueOf(OPT_SDAID)));
                    } else if (env.containsKey("GP_AID")) {
                        gp = GlobalPlatform.connect(channel, AID.fromString(env.get("GP_AID")));
                    } else {
                        // Oracle only applies if no other arguments given
                        gp = GlobalPlatform.discover(channel);
                        // FIXME: would like to get AID from oracle as well.
                    }

                    // Don't do sanity checks, just run asked commands
                    if (args.has(OPT_FORCE))
                        gp.setStrict(false);

                    // Extract information
                    if (args.has(OPT_INFO)) {
                        GPData.dump(channel);
                    }

                    // Normally assume a single master key
                    final GPSessionKeyProvider keys;

                    if (args.has(OPT_KEYS)) {
                        // keys come from custom provider
                        fail("Not yet implemented");
                        keys = PlaintextKeys.fromMasterKey(GPData.getDefaultKey());
                    } else if (args.has(OPT_ORACLE)) {
                        keys = PythiaKeys.ask(card.getATR().getBytes(), GPData.fetchCPLC(channel), GPData.fetchKeyInfoTemplate(channel));
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
                            Optional<SecureChannelParameters> params = SecureChannelParameters.fromEnvironment();
                            // XXX: better checks for exclusive key options
                            if (args.has(OPT_KEY_MAC) && args.has(OPT_KEY_ENC) && args.has(OPT_KEY_DEK)) {
                                GPKey enc = new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_KEY_ENC)));
                                GPKey mac = new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_KEY_MAC)));
                                GPKey dek = new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_KEY_DEK)));
                                keyz = PlaintextKeys.fromKeys(enc, mac, dek);
                            } else if (params.isPresent()) {
                                keyz = (PlaintextKeys) params.get().getSessionKeys();
                            } else {
                                if (needsAuthentication(args)) {
                                    System.out.println("Warning: no keys given, using default test key " + HexUtils.bin2hex(GPData.defaultKeyBytes));
                                }
                                keyz = PlaintextKeys.fromMasterKey(GPData.getDefaultKey());
                            }
                        }

                        // "gp -l -emv" should still work
                        if (args.has(OPT_VISA2)) {
                            keyz.setDiversifier(VISA2);
                        } else if (args.has(OPT_EMV)) {
                            keyz.setDiversifier(EMV);
                        } else if (args.has(OPT_KDF3)) {
                            keyz.setDiversifier(KDF3);
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

                    // list access rules from ARA-M
                    if (args.has(OPT_ACR_LIST_ARAM)) {
                        SEAccessControlUtility.acrList(gp);
                    }

                    // Authenticate, only if needed
                    if (needsAuthentication(args)) {
                        EnumSet<APDUMode> mode = GlobalPlatform.defaultMode.clone();
                        // Override default mode if needed.
                        if (args.has(OPT_SC_MODE)) {
                            mode.clear();
                            for (Object s : args.valuesOf(OPT_SC_MODE)) {
                                mode.add(APDUMode.fromString((String) s));
                            }
                        }

                        // IMPORTANT PLACE. Possibly brick the card now, if keys don't match.
                        gp.openSecureChannel(keys, null, 0, mode);

                        // --secure-apdu or -s
                        if (args.has(OPT_SECURE_APDU)) {
                            for (Object s : args.valuesOf(OPT_SECURE_APDU)) {
                                CommandAPDU c = new CommandAPDU(HexUtils.stringToBin((String) s));
                                gp.transmit(c);
                            }
                        }

                        // list access rules from ARA-* via STORE DATA
                        if (args.has(OPT_ACR_LIST)) {
                            SEAccessControl.AcrListFetcher fetcher = new SEAccessControl.AcrListFetcher(gp);
                            byte[] r = fetcher.get(args.has(OPT_ACR_AID) ? AID.fromString(args.valueOf(OPT_ACR_AID)) : null);
                            SEAccessControl.AcrListResponse resp = SEAccessControl.AcrListResponse.fromBytes(r);
                            SEAccessControl.printList(resp.acrList);
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
                            List<AID> aids = args.valuesOf(OPT_DELETE).stream().map(a -> AID.fromString(a)).collect(Collectors.toList());
                            for (AID aid : aids) {
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
                            List<CAPFile> caps = getCapFileList(args, OPT_UNINSTALL);
                            for (CAPFile instcap : caps) {
                                AID aid = instcap.getPackageAID();
                                if (!gp.getRegistry().allAIDs().contains(aid)) {
                                    System.out.println(aid + " is not present on card!");
                                } else {
                                    gp.deleteAID(aid, true);
                                    System.out.println(aid + " deleted.");
                                }
                            }
                        }

                        // --load <applet.cap>
                        if (args.has(OPT_LOAD)) {
                            List<CAPFile> caps = getCapFileList(args, OPT_LOAD);
                            for (CAPFile loadcap : caps) {
                                if (isVerbose) {
                                    loadcap.dump(System.out);
                                }
                                try {
                                    AID target = null;
                                    AID dapdomain = null;
                                    boolean dapRequired = false;

                                    // Override target and check for DAP
                                    if (args.has(OPT_TO)) {
                                        target = AID.fromString(args.valueOf(OPT_TO));
                                        if (gp.getRegistry().getDomain(target).getPrivileges().has(Privilege.DAPVerification))
                                            dapRequired = true;
                                    }

                                    // Check if DAP block is required
                                    for (GPRegistryEntryApp e : gp.getRegistry().allDomains()) {
                                        if (e.getPrivileges().has(Privilege.MandatedDAPVerification))
                                            dapRequired = true;
                                    }

                                    // Check if DAP is overriden
                                    if (args.has(OPT_DAP_DOMAIN)) {
                                        dapdomain = AID.fromString(args.valueOf(OPT_DAP_DOMAIN));
                                        Privileges p = gp.getRegistry().getDomain(dapdomain).getPrivileges();
                                        if (!(p.has(Privilege.DAPVerification) || p.has(Privilege.MandatedDAPVerification))) {
                                            fail("Specified DAP domain does not have (Mandated)DAPVerification privilege: " + p.toString());
                                        }
                                    }

                                    // XXX: figure out right signature type in a better way
                                    if (dapRequired) {
                                        byte[] dap = args.has(OPT_SHA256) ? loadcap.getMetaInfEntry(CAPFile.DAP_RSA_V1_SHA256_FILE) : loadcap.getMetaInfEntry(CAPFile.DAP_RSA_V1_SHA1_FILE);
                                        gp.loadCapFile(loadcap, target, dapdomain == null ? target : dapdomain, dap, args.has(OPT_SHA256) ? "SHA-256" : "SHA1");
                                    } else {
                                        gp.loadCapFile(loadcap, target);
                                    }
                                } catch (GPException e) {
                                    switch (e.sw) {
                                        case 0x6A80:
                                            System.err.println("Applet loading failed. Are you sure the card can handle it?");
                                            break;
                                        case 0x6985:
                                            System.err.println("Applet loading not allowed. Are you sure the domain can accept it?");
                                            break;
                                        default:
                                            // Do nothing. Here for findbugs
                                    }
                                    throw e;
                                }
                            }
                        }

                        // --put-key <keyfile.pem>
                        // Load a RSA public key (for DAP purposes)
                        if (args.has(OPT_PUT_KEY)) {
                            int keyVersion = 0x73; // Default DAP version
                            if (args.has(OPT_NEW_KEY_VERSION)) {
                                keyVersion = GPUtils.intValue(args.valueOf(OPT_NEW_KEY_VERSION).toString());
                            }

                            try (FileInputStream fin = new FileInputStream(new File(args.valueOf(OPT_PUT_KEY).toString()))) {
                                // Get public key
                                PublicKey key = GPCrypto.pem2pubkey(fin);
                                if (key instanceof RSAPublicKey) {
                                    gp.putKey((RSAPublicKey) key, keyVersion);
                                }
                            }
                        }

                        // --install <applet.cap> (--applet <aid> --create <aid> --privs <privs> --params <params>)
                        if (args.has(OPT_INSTALL)) {
                            final File capfile;
                            capfile = (File) args.valueOf(OPT_INSTALL);

                            final CAPFile instcap;
                            try (FileInputStream fin = new FileInputStream(capfile)) {
                                instcap = CAPFile.fromStream(fin);
                            }

                            if (args.has(OPT_VERBOSE)) {
                                instcap.dump(System.out);
                            }

                            GPRegistry reg = gp.getRegistry();

                            // Remove existing load file
                            if (args.has(OPT_FORCE) && reg.allPackageAIDs().contains(instcap.getPackageAID())) {
                                gp.deleteAID(instcap.getPackageAID(), true);
                            }

                            // Load
                            // TODO: handle DAP here as well
                            if (instcap.getAppletAIDs().size() <= 1) {
                                try {
                                    AID target = null;
                                    if (args.has(OPT_TO))
                                        target = AID.fromString(args.valueOf(OPT_TO));
                                    gp.loadCapFile(instcap, target);
                                    System.out.println("CAP loaded");
                                } catch (GPException e) {
                                    if (e.sw == 0x6985 || e.sw == 0x6A80) {
                                        System.err.println("Loading failed. Are you sure the CAP file (JC version, packages, sizes) is compatible with your card?");
                                    }
                                    throw e;
                                }
                            }

                            // Install
                            final AID appaid;
                            final AID instanceaid;
                            if (instcap.getAppletAIDs().size() == 0) {
                                return;
                            } else if (instcap.getAppletAIDs().size() > 1) {
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

                            Privileges privs = getInstPrivs(args);

                            // Remove existing default app
                            if (args.has(OPT_FORCE) && (reg.getDefaultSelectedAID() != null && privs.has(Privilege.CardReset))) {
                                gp.deleteAID(reg.getDefaultSelectedAID(), false);
                            }

                            // warn
                            if (gp.getRegistry().allAppletAIDs().contains(instanceaid)) {
                                System.err.println("WARNING: Applet " + instanceaid + " already present on card");
                            }

                            // shoot
                            gp.installAndMakeSelectable(instcap.getPackageAID(), appaid, instanceaid, privs, getInstParams(args), null);
                        }

                        // --create <aid> (--applet <aid> --package <aid> or --cap <cap>)
                        if (args.has(OPT_CREATE) && !args.has(OPT_INSTALL)) {
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
                            // Arguments check
                            if ((args.has(OPT_ALLOW_FROM) || args.has(OPT_ALLOW_TO)) && args.has(OPT_PARAMS)) {
                                fail("SSD extradition options can't be used with SSD installation parameters");
                            }

                            // Default AID-s
                            AID packageAID = new AID("A0000001515350");
                            AID appletAID = new AID("A000000151535041");

                            // Override if necessary
                            if (args.has(OPT_PACKAGE) && args.has(OPT_APPLET)) {
                                packageAID = AID.fromString(args.valueOf(OPT_PACKAGE));
                                appletAID = AID.fromString(args.valueOf(OPT_APPLET));
                            } else {
                                System.out.println("Note: using default AID-s for SSD instantiation: " + appletAID + " from " + packageAID);
                            }
                            AID instanceAID = AID.fromString(args.valueOf(OPT_DOMAIN));

                            // Extra privileges
                            Privileges privs = getInstPrivs(args);
                            privs.add(Privilege.SecurityDomain);

                            // Extradition rules
                            byte[] params = new byte[0];
                            if (args.has(OPT_PARAMS)) {
                                params = getInstParams(args);
                            } else {
                                if (args.has(OPT_ALLOW_TO)) {
                                    params = GPUtils.concatenate(params, new byte[]{(byte) 0x82, 0x01, 0x20});
                                }
                                if (args.has(OPT_ALLOW_FROM)) {
                                    params = GPUtils.concatenate(params, new byte[]{(byte) 0x87, 0x01, 0x20});
                                }
                            }

                            // shoot
                            gp.installAndMakeSelectable(packageAID, appletAID, instanceAID, privs, params, null);
                        }

                        // --move <AID>
                        if (args.has(OPT_MOVE)) {
                            if (!args.has(OPT_TO)) {
                                fail("Specify extradition target with --" + OPT_TO);
                            }
                            AID what = AID.fromString(args.valueOf(OPT_MOVE));
                            AID to = AID.fromString(args.valueOf(OPT_TO));

                            gp.extradite(what, to);
                        }

                        // --store-data <XX>
                        // This will split the data, if necessary
                        if (args.has(OPT_STORE_DATA_BLOB)) {
                            List<byte[]> blobs = args.valuesOf(OPT_STORE_DATA_BLOB).stream().map(e -> HexUtils.stringToBin((String) e)).collect(Collectors.toList());
                            for (byte[] blob : blobs) {
                                if (args.has(OPT_APPLET)) {
                                    gp.personalize(AID.fromString(args.valueOf(OPT_APPLET)), blob, 0x01);
                                } else {
                                    gp.storeData(blob, 0x1);
                                }
                            }
                        }

                        // --store-data-chunk
                        // This will collect the chunks and send them one by one
                        if (args.has(OPT_STORE_DATA)) {
                            List<byte[]> blobs = args.valuesOf(OPT_STORE_DATA).stream().map(e -> HexUtils.stringToBin((String) e)).collect(Collectors.toList());
                            if (args.has(OPT_APPLET)) {
                                gp.personalize(AID.fromString(args.valueOf(OPT_APPLET)), blobs, 0x01);
                            } else {
                                gp.storeData(blobs, 0x1);
                            }
                        }

                        if (args.has(OPT_ACR_ADD)) {
                            AID aid = null;
                            byte[] hash = null;
                            AID araAid = SEAccessControl.ACR_AID;
                            if (args.has(OPT_APPLET))
                                aid = AID.fromString(args.valueOf(OPT_APPLET));
                            if (args.has(OPT_ACR_CERT_HASH))
                                hash = HexUtils.stringToBin((String) args.valueOf(OPT_ACR_CERT_HASH));
                            if (args.has(OPT_ACR_AID))
                                araAid = AID.fromString((String) args.valueOf(OPT_ACR_AID));
                            if (!args.has(OPT_ACR_RULE)) {
                                System.err.println("Must specify an access rule with -" + OPT_ACR_RULE + " (00, 01 or an apdu filter)");
                            }
                            if (hash != null && hash.length != 20) {
                                fail("certificate hash must be 20 bytes");
                            }
                            SEAccessControlUtility.acrAdd(gp, araAid, aid, hash, HexUtils.stringToBin((String) args.valueOf(OPT_ACR_RULE)));
                        }

                        // --acr-delete
                        if (args.has(OPT_ACR_DELETE)) {
                            AID araAid = SEAccessControl.ACR_AID;
                            if (args.has(OPT_ACR_AID))
                                araAid = AID.fromString(args.valueOf(OPT_ACR_AID));

                            AID aid = null;
                            if (args.has(OPT_APPLET)) {
                                aid = AID.fromString(OPT_APPLET);
                            }

                            byte[] hash = null;
                            if (args.has(OPT_ACR_CERT_HASH)) {
                                hash = HexUtils.stringToBin((String) args.valueOf(OPT_ACR_CERT_HASH));
                                if (hash.length != 20)
                                    fail("certificate hash must be 20 bytes");
                            }

                            SEAccessControlUtility.acrDelete(gp, araAid, aid, hash);
                        }

                        // --lock-card
                        if (args.has(OPT_LOCK_CARD)) {
                            gp.setCardStatus(GPData.lockedStatus);
                        }
                        // --unlock-card
                        if (args.has(OPT_UNLOCK_CARD)) {
                            gp.setCardStatus(GPData.securedStatus);
                        }
                        // --initialize-card
                        if (args.has(OPT_INITIALIZE_CARD)) {
                            gp.setCardStatus(GPData.initializedStatus);
                        }
                        // --secure-card
                        if (args.has(OPT_SECURE_CARD)) {
                            // Skip INITIALIZED
                            GPRegistryEntryApp isd = gp.getRegistry().getISD();
                            if (isd == null) {
                                GPCommands.listRegistry(gp.getRegistry(), System.out, true);
                                fail("ISD is null");
                            }
                            if (isd.getLifeCycle() != GPData.initializedStatus) {
                                if (args.has(OPT_FORCE)) {
                                    System.out.println("Note: forcing status to INITIALIZED");
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

                            System.out.println("Default " + new_key.toString() + " set as master key for " + gp.getAID());
                        }

                        // --lock
                        if (args.has(OPT_LOCK) || (args.has(OPT_LOCK_ENC) && args.has(OPT_LOCK_MAC) && args.has(OPT_LOCK_DEK))) {
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

                            // If a specific new key version is specified, use that instead.
                            if (args.has(OPT_NEW_KEY_VERSION)) {
                                new_version = GPUtils.intValue((String) args.valueOf(OPT_NEW_KEY_VERSION));
                                replace = false;
                                System.out.println("New version: " + new_version);
                            }

                            // Get key value or values
                            List<GPKey> updatekeys = new ArrayList<>();
                            if (args.has(OPT_LOCK_ENC) && args.has(OPT_LOCK_MAC) && args.has(OPT_LOCK_DEK)) {
                                updatekeys.add(new GPKey(new_version, 1, new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_LOCK_ENC)))));
                                updatekeys.add(new GPKey(new_version, 2, new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_LOCK_MAC)))));
                                updatekeys.add(new GPKey(new_version, 3, new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_LOCK_DEK)))));
                            } else {
                                GPKey nk = new GPKey(HexUtils.stringToBin((String) args.valueOf(OPT_LOCK)));
                                // We currently use the same key, diversification is missing
                                updatekeys.add(new GPKey(new_version, 1, nk));
                                updatekeys.add(new GPKey(new_version, 2, nk));
                                updatekeys.add(new GPKey(new_version, 3, nk));
                            }

                            // XXX: this is uggely
                            Type t = gp.getSCPVersion() == 3 ? Type.AES : Type.DES3;
                            for (GPKey k : updatekeys) {
                                k.become(t);
                            }

                            gp.putKeys(updatekeys, replace);

                            if (args.has(OPT_LOCK)) {
                                System.out.println("Card locked with: " + HexUtils.bin2hex(HexUtils.stringToBin((String) args.valueOf(OPT_LOCK))));
                                System.out.println("Write this down, DO NOT FORGET/LOSE IT!");
                            } else {
                                System.out.println("Card locked with new keys.");
                                System.out.println("Write them down, DO NOT FORGET/LOSE THEM!");
                            }
                        }

                        // --make-default <aid>
                        if (args.has(OPT_MAKE_DEFAULT)) {
                            gp.makeDefaultSelected(AID.fromString(args.valueOf(OPT_MAKE_DEFAULT)));
                        }

                        // --rename-isd
                        if (args.has(OPT_RENAME_ISD)) {
                            gp.renameISD(AID.fromString(args.valueOf(OPT_RENAME_ISD)));
                        }
                        // --set-pre-perso
                        if (args.has(OPT_SET_PRE_PERSO)) {
                            byte[] payload = HexUtils.stringToBin((String) args.valueOf(OPT_SET_PRE_PERSO));
                            if (args.has(OPT_TODAY)) {
                                System.arraycopy(GPData.CPLC.today(), 0, payload, 2, 2);
                            }
                            GPCommands.setPrePerso(gp, payload);
                        }
                        // --set-perso
                        if (args.has(OPT_SET_PERSO)) {
                            byte[] payload = HexUtils.stringToBin((String) args.valueOf(OPT_SET_PERSO));
                            if (args.has(OPT_TODAY)) {
                                System.arraycopy(GPData.CPLC.today(), 0, payload, 2, 2);
                            }
                            GPCommands.setPerso(gp, payload);
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
        if (args.has(OPT_PARAMS)) {
            String arg = (String) args.valueOf(OPT_PARAMS);
            return HexUtils.stringToBin(arg);
        } else {
            return new byte[0];
        }
    }

    private static boolean ignoreReader(String name) {
        String ignore = System.getenv("GP_READER_IGNORE");
        if (ignore != null) {
            String[] names = ignore.toLowerCase().split(";");
            for (String n : names) {
                if (name.toLowerCase().contains(n)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<CAPFile> getCapFileList(OptionSet args, String arg) {
        return args.valuesOf(arg).stream().map(e -> {
            try (FileInputStream fin = new FileInputStream((File) e)) {
                return CAPFile.fromStream(fin);
            } catch (IOException x) {
                fail("Could not read CAP: " + x.getMessage());
                return null; // For compiler, fail() quits the process
            }
        }).collect(Collectors.toList());
    }

    private static boolean needsAuthentication(OptionSet args) {
        String[] yes = new String[]{OPT_LIST, OPT_LOAD, OPT_INSTALL, OPT_DELETE, OPT_DELETE_KEY, OPT_CREATE,
                OPT_ACR_ADD, OPT_ACR_DELETE, OPT_LOCK, OPT_UNLOCK, OPT_LOCK_ENC, OPT_LOCK_MAC, OPT_LOCK_DEK, OPT_MAKE_DEFAULT,
                OPT_UNINSTALL, OPT_SECURE_APDU, OPT_DOMAIN, OPT_LOCK_CARD, OPT_UNLOCK_CARD, OPT_LOCK_APPLET, OPT_UNLOCK_APPLET,
                OPT_STORE_DATA_BLOB, OPT_STORE_DATA, OPT_INITIALIZE_CARD, OPT_SECURE_CARD, OPT_RENAME_ISD, OPT_SET_PERSO, OPT_SET_PRE_PERSO, OPT_MOVE,
                OPT_PUT_KEY, OPT_ACR_AID, OPT_ACR_LIST};

        for (String s : yes) {
            if (args.has(s)) {
                return true;
            }
        }
        return false;
    }

    private static void fail(String msg) {
        System.err.println(msg);
        System.exit(1);
    }

    private static void verbose(String s) {
        if (isVerbose) {
            System.out.println("# " + s);
        }
    }
}
