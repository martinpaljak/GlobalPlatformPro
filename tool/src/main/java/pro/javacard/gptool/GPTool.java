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
package pro.javacard.gptool;

import apdu4j.core.*;
import apdu4j.pcsc.CardBIBO;
import apdu4j.pcsc.PCSCReader;
import apdu4j.pcsc.TerminalManager;
import apdu4j.pcsc.terminals.LoggingCardTerminal;
import com.google.auto.service.AutoService;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.*;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession.APDUMode;
import pro.javacard.gptool.emv.DGI;
import pro.javacard.gptool.keys.PlaintextKeys;
import pro.javacard.pace.AESSecureChannel;
import pro.javacard.pace.PACE;
import pro.javacard.pace.PACEException;

import javax.crypto.Cipher;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static pro.javacard.gp.GPSecureChannelVersion.SCP.*;

// Does the CLI parameter parsing and associated execution
@AutoService(SmartCardApp.class)
public final class GPTool extends GPCommandLineInterface implements SimpleSmartCardApp {
    // NOTE: can't have a logger here, as it is set up based on args and env. This class should only use stdout/stderr.

    private static boolean isVerbose = false;
    private static boolean isTrace = false;

    static final String ENV_GP_AID = "GP_AID";
    static final String ENV_GP_READER = "GP_READER";
    static final String ENV_GP_READER_IGNORE = "GP_READER_IGNORE";
    static final String ENV_GP_TRACE = "GP_TRACE";
    static final String ENV_GP_PCSC_RESET = "GP_PCSC_RESET";
    static final String ENV_GP_PCSC_EXCLUSIVE = "GP_PCSC_EXCLUSIVE";
    static final String ENV_GP_PCSC_TRANSACT = "GP_PCSC_TRANSACT";

    static void setupLogging(OptionSet args) {
        // Set up slf4j simple in a way that pleases us
        System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
        System.setProperty("org.slf4j.simpleLogger.levelInBrackets", "true");
        System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");

        if (args.has(OPT_VERBOSE)) {
            isVerbose = true;
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info");
        }
        if (args.has(OPT_DEBUG) && args.has(OPT_VERBOSE))
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        if (args.has(OPT_DEBUG) && System.getenv().containsKey(ENV_GP_TRACE)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
            isTrace = true;
        }
    }

    // Explicitly public, to not forget the need for apdu4j
    public GPTool() {
    }

    private static boolean preamble = true;

    private static void showPreamble(String[] argv, OptionSet args) {
        if (preamble) {
            // dump relevant environment and command line variables in verbose+ mode
            if (args.has(OPT_VERBOSE) || args.has(OPT_DEBUG) || args.has(OPT_INFO)) {
                List<String> gpenv = System.getenv().entrySet().stream().filter(e -> e.getKey().startsWith("GP_")).map(e -> String.format("%s=%s", e.getKey(), e.getValue())).collect(Collectors.toList());
                if (gpenv.size() > 0)
                    System.out.println("# " + String.join(" ", gpenv));
                System.out.println("# gp " + String.join(" ", argv));
            }
            if (args.has(OPT_VERBOSE) || args.has(OPT_DEBUG) || args.has(OPT_INFO) || args.has(OPT_VERSION)) {
                System.out.printf("# GlobalPlatformPro %s%n", GPSession.getVersion());
                System.out.printf("# Running on %s %s %s", System.getProperty("os.name"), System.getProperty("os.version"), System.getProperty("os.arch"));
                System.out.printf(", Java %s by %s%n", System.getProperty("java.version"), System.getProperty("java.vendor"));
            }
            try {
                // Test for unlimited crypto
                if (Cipher.getMaxAllowedKeyLength("AES") == 128) {
                    System.err.println("# Error: unlimited crypto policy is NOT installed!");
                    System.err.println("# Please install and use JDK 11 LTS or later");
                }
            } catch (NoSuchAlgorithmException e) {
                System.err.println("# Error: no AES support in JRE?");
            }
        }
        preamble = false;
    }

    // To keep basic gp.jar together with apdu4j app, this is just a minimalist wrapper
    public static void main(String[] argv) {
        Card c = null;
        int ret = 1;

        boolean resetOnDisconnect = Boolean.parseBoolean(System.getenv().getOrDefault(ENV_GP_PCSC_RESET, "false"));
        boolean exclusive = Boolean.parseBoolean(System.getenv().getOrDefault(ENV_GP_PCSC_EXCLUSIVE, "false"));
        boolean transact = Boolean.parseBoolean(System.getenv().getOrDefault(ENV_GP_PCSC_TRANSACT, "true"));

        try {
            OptionSet args = parseArguments(argv);
            setupLogging(args);
            showPreamble(argv, args);

            if (onlyHasArg(args, OPT_VERSION))
                return;

            // FIXME: have "cardlessCommands()"
            if (onlyHasArg(args, OPT_CAP)) {
                CAPFile cap = CAPFile.fromFile(args.valueOf(OPT_CAP).toPath());
                cap.dump(System.out);
                return;
            }

            TerminalManager terminalManager = TerminalManager.getDefault();
            List<PCSCReader> readers = TerminalManager.listPCSC(terminalManager.terminals().list(), null, false);

            if (args.has(OPT_READER) && !args.hasArgument(OPT_READER)) {
                System.out.println("Available readers:");
                readers.forEach((r) -> System.out.printf("- %s%n", r.getName()));
            }
            String useReader = args.hasArgument(OPT_READER) ? args.valueOf(OPT_READER) : System.getenv(ENV_GP_READER);
            String ignoreReader = System.getenv(ENV_GP_READER_IGNORE);

            // FIXME: simplify
            Optional<CardTerminal> reader = TerminalManager.getLucky(TerminalManager.dwimify(readers, useReader, ignoreReader), terminalManager.terminals());

            if (reader.isEmpty()) {
                System.err.println("Specify reader with -r/$GP_READER; available readers:");
                readers.forEach((r) -> System.err.printf("- %s%n", r.getName()));
                System.exit(1);
            }
            if (args.has(OPT_PCSC_EXCLUSIVE))
                exclusive = true;

            reader = reader.map(e -> args.has(OPT_DEBUG) ? LoggingCardTerminal.getInstance(e) : e);
            String protocol = exclusive ? "EXCLUSIVE;*" : "*";
            c = reader.get().connect(protocol);
            if (transact)
                c.beginExclusive();
            ret = new GPTool().run(CardBIBO.wrap(c), argv);
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid argument: " + e.getMessage());
            if (isTrace)
                e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            if (isTrace)
                e.printStackTrace();
        } finally {
            if (c != null) {
                if (transact) {
                    try {
                        c.endExclusive();
                    } catch (CardException e) {
                        System.err.println("Exception when ending card transaction: " + e.getMessage());
                        if (isTrace)
                            e.printStackTrace();
                    }
                }
                try {
                    c.disconnect(resetOnDisconnect);
                } catch (CardException e) {
                    System.err.println("Exception when disconnecting card: " + e.getMessage());
                    if (isTrace)
                        e.printStackTrace();
                }
            }
        }
        System.exit(ret);
    }

    static boolean onlyHasArg(OptionSet args, OptionSpec<?> s) {
        long needle = args.specs().stream().filter(args::has).count();
        long hay = args.specs().stream().filter(e -> args.has(e) && e != s).count();
        return needle == 1 && hay == 0;
    }

    // For running in apdu4j mode
    @Override
    public int run(BIBO bibo, String[] argv) {
        try {
            OptionSet args = parseArguments(argv);
            setupLogging(args);

            showPreamble(argv, args);
            if (onlyHasArg(args, OPT_VERSION))
                return 0;

            // Load a CAP file, if specified
            CAPFile cap = null;
            if (args.has(OPT_CAP)) {
                File capfile = args.valueOf(OPT_CAP);
                cap = CAPFile.fromFile(capfile.toPath());
            }

            // Now actually talk to possible terminals
            APDUBIBO channel = new APDUBIBO(bibo);
            // Run PACE to enable contactless interface
            if (args.has(OPT_PACE) || args.has(OPT_PACE_SM)) {
                byte[] aid = args.has(OPT_PACE) ? args.valueOf(OPT_PACE).getBytes() : args.valueOf(OPT_PACE_SM).getBytes();
                try {
                    PACE pace = PACE.executePACE(channel, aid, args.valueOf(OPT_CAN), args.valueOf(OPT_PACE_CURVE));
                    if (args.has(OPT_PACE_SM)) {
                        channel = new APDUBIBO(new AESSecureChannel(pace.getENC(), pace.getMAC(), bibo));
                    }
                } catch (PACEException | GeneralSecurityException e) {
                    System.err.println("Could not run PACE: " + e.getMessage());
                    return 1;
                }
            }

            // Send all raw APDU-s to the default-selected application of the card
            if (args.has(OPT_APDU)) {
                // Select the application, if present
                AID target = null;
                if (args.has(OPT_APPLET)) {
                    target = args.valueOf(OPT_APPLET);
                } else if (cap != null) {
                    target = cap.getAppletAIDs().get(0); // FIXME: generalize and only work if one
                }
                if (target != null) {
                    verbose("Selecting " + target);
                    channel.transmit(new CommandAPDU(0x00, GPSession.INS_SELECT, 0x04, 0x00, target.getBytes()));
                }
                for (byte[] s : args.valuesOf(OPT_APDU).stream().map(APDUParsers::stringToAPDU).collect(Collectors.toList())) {
                    CommandAPDU c = new CommandAPDU(s);
                    ResponseAPDU r = channel.transmit(c);
                    if (r.getSW() == 0x9000 && r.getData().length > 0)
                        System.out.println(APDUParsers.visualize_structure(r.getData()));
                }
            }

            Map<String, String> env = System.getenv();

            // GlobalPlatform specific
            final EnumSet<APDUMode> mode = GPSession.defaultMode.clone();
            // Override default mode if needed.
            if (args.has(OPT_SC_MODE)) {
                mode.clear();
                mode.addAll(args.valuesOf(OPT_SC_MODE));
            }
            final GPSession gp;
            if (args.has(OPT_CONNECT)) {
                gp = GPSession.connect(channel, args.valueOf(OPT_CONNECT));
            } else if (env.containsKey(ENV_GP_AID)) {
                AID aid = AID.fromString(env.get(ENV_GP_AID));
                verbose(String.format("Connecting to $%s (%s)", ENV_GP_AID, aid));
                gp = GPSession.connect(channel, aid);
            } else {
                gp = GPSession.discover(channel);
            }

            // Override block size for stupidly broken readers.
            // See https://github.com/martinpaljak/GlobalPlatformPro/issues/32
            // The name of the option comes from a common abbreviation as well as dd utility
            optional(args, OPT_BS).ifPresent(gp::setBlockSize);

            // Delegated management
            if (args.has(OPT_DM_KEY)) {
                Optional<PrivateKey> dmkey = args.valueOf(OPT_DM_KEY).getPrivate();

                if (dmkey.isEmpty() || !(dmkey.get() instanceof RSAPrivateKey)) {
                    throw new IllegalArgumentException("Only RSA private keys are supported for DM");
                }
                gp.setTokenizer(DMTokenizer.forPrivateKey((RSAPrivateKey) dmkey.get()));
            } else if (args.has(OPT_DM_TOKEN)) {
                byte[] token = args.valueOf(OPT_DM_TOKEN).value();
                gp.setTokenizer(DMTokenizer.forToken(token));
            }

            if (args.has(OPT_RECEIPT_KEY)) {
                // XXX: refactor receipts.
                ReceiptVerifier verifier = new ReceiptVerifier.AESReceiptVerifier(args.valueOf(OPT_RECEIPT_KEY).v(), args.has(OPT_FORCE));
                gp.setVerifier(verifier);
            }

            // Extract information
            if (args.has(OPT_INFO)) {
                GPData.dump(channel);
            }

            // Normally assume a single master key
            final GPCardKeys keys;

            Optional<GPCardKeys> key = keyFromPlugin(args.valueOf(OPT_KEY));
            if (key.isPresent()) {
                // keys come from custom or plaintext provider
                keys = key.get();
            } else {
                Optional<PlaintextKeys> envKeys = PlaintextKeys.fromEnvironment();

                final Optional<PlaintextKeys> cliKeys;
                if (args.has(OPT_KEY_ENC) && args.has(OPT_KEY_MAC) && args.has(OPT_KEY_DEK)) {
                    cliKeys = Optional.of(PlaintextKeys.fromKeys(args.valueOf(OPT_KEY_ENC).v(), args.valueOf(OPT_KEY_MAC).v(), args.valueOf(OPT_KEY_DEK).v()));
                } else cliKeys = Optional.empty();
                if (envKeys.isPresent() && cliKeys.isPresent()) {
                    System.err.println("# Warning: keys set on command line shadow environment!");
                } else if (envKeys.isEmpty() && cliKeys.isEmpty()) {
                    if (args.has(OPT_SAD)) {
                        System.err.println("Error: no keys given");
                        return 1;
                    } else
                        System.err.println("# Warning: no keys given, defaulting to " + HexUtils.bin2hex(PlaintextKeys.DEFAULT_KEY()));
                }
                keys = cliKeys.or(() -> envKeys).orElse(PlaintextKeys.defaultKey());
            }

            // Legacy KDF option and key version
            if (keys instanceof PlaintextKeys) {
                PlaintextKeys keyz = (PlaintextKeys) keys;

                if (args.has(OPT_KEY_KDF)) {
                    keyz.setDiversifier(PlaintextKeys.kdf_templates.getOrDefault(args.valueOf(OPT_KEY_KDF), args.valueOf(OPT_KEY_KDF)));
                }

                // Set/override key version
                optional(args, OPT_KEY_VERSION).ifPresent(keyz::setVersion);
            }

            if (args.has(OPT_PROFILE)) {
                Optional<GPCardProfile> p = GPCardProfile.fromName(args.valueOf(OPT_PROFILE));
                if (p.isEmpty()) {
                    System.err.printf("Unknown profile '%s', known profiles: %s%n", args.valueOf(OPT_PROFILE), String.join(", ", GPCardProfile.profiles.keySet()));
                    return 1;
                }
                gp.setProfile(p.get());
            }

            // Authenticate, only if needed
            if (needsAuthentication(args)) {
                // IMPORTANT PLACE. Possibly brick the card now, if keys don't match.

                try {
                    // S16 will be gracefully tried if default (S8) returns wrong length, but can be forced by challenge length
                    gp.openSecureChannel(keys, null, args.has(OPT_S16) ? GPCrypto.random(16) : null, mode);
                } catch (GPException e) {
                    System.err.println("Failed to open secure channel: " + e.getMessage() + "\nRead more from https://github.com/martinpaljak/GlobalPlatformPro/wiki/Keys");
                    return 1;
                }

                // --secure-apdu or -s
                if (args.has(OPT_SECURE_APDU)) {
                    for (byte[] s : args.valuesOf(OPT_SECURE_APDU).stream().map(APDUParsers::stringToAPDU).collect(Collectors.toList())) {
                        CommandAPDU c = new CommandAPDU(s);
                        ResponseAPDU r = gp.transmit(c);
                        if (r.getData().length > 0 && r.getSW() == 0x9000) {
                            System.out.println(APDUParsers.visualize_structure(r.getData()));
                        }
                    }
                }

                // --delete <aid>
                if (args.has(OPT_DELETE)) {
                    if (!args.has(OPT_FORCE) && !args.has(OPT_SAD))
                        warnIfNoDelegatedManagement(gp);

                    GPRegistry reg = gp.getRegistry();

                    // DWIM: assume that default selected is the one to be deleted
                    if (args.has(OPT_DEFAULT)) {
                        Optional<AID> def = reg.getDefaultSelectedAID();
                        if (def.isPresent()) {
                            gp.deleteAID(def.get(), false);
                        } else {
                            System.err.println("Could not identify default selected application!");
                        }
                    }
                    boolean failure = false;
                    List<AID> aidList = new ArrayList<>(args.valuesOf(OPT_DELETE));
                    for (AID aid : aidList) {
                        try {
                            // If the AID represents a package and force is enabled, delete deps as well
                            boolean deleteDeps = reg.allPackageAIDs().contains(aid) && args.has(OPT_FORCE);
                            gp.deleteAID(aid, deleteDeps);
                        } catch (GPException e) {
                            failure = true;
                            if (!reg.allAIDs().contains(aid)) {
                                System.err.println("Could not delete AID (not present on card): " + aid);
                            } else {
                                if (e.sw == 0x6985) {
                                    System.err.printf("Could not delete %s (0x6985). Some app still active?%n", aid);
                                } else {
                                    System.err.printf("Could not delete AID %s: %s%n", aid, GPData.sw2str(e.sw));
                                }
                            }
                            // Do not return errors from -delete to behave like rm
                        }
                    }
                    // #142: Behave like rm -f: fail if there was an error, unless -f
                    if (failure && !args.has(OPT_FORCE))
                        return 1;
                }

                // --uninstall <cap>
                if (args.has(OPT_UNINSTALL)) {
                    if (!args.has(OPT_FORCE) && !args.has(OPT_SAD))
                        warnIfNoDelegatedManagement(gp);
                    List<CAPFile> caps = getCapFileList(args, OPT_UNINSTALL);
                    boolean failure = false;
                    for (CAPFile instcap : caps) {
                        AID aid = instcap.getPackageAID();
                        // Simple warning
                        if (!gp.getRegistry().allAIDs().contains(aid)) {
                            System.err.println(aid + " is not present on card!");
                        }
                        try {
                            gp.deleteAID(aid, true);
                            System.out.println(aid + " deleted.");
                        } catch (GPException e) {
                            failure = true;
                        }
                    }
                    // #142: Behave like rm -f: fail if there was an error, unless -f
                    if (failure && !args.has(OPT_FORCE))
                        return 1;
                }

                // --load <applet.cap>
                if (args.has(OPT_LOAD)) {
                    if (!args.has(OPT_FORCE) && !args.has(OPT_SAD))
                        warnIfNoDelegatedManagement(gp);
                    List<CAPFile> caps = getCapFileList(args, OPT_LOAD);

                    GPRegistry reg = gp.getRegistry();
                    // Remove existing load file if needed
                    if (args.has(OPT_FORCE)) {
                        for (CAPFile loadcap : caps) {
                            if (reg.allPackageAIDs().contains(loadcap.getPackageAID())) {
                                verbose("removing existing package " + loadcap.getPackageName() + " " + loadcap.getPackageAID());
                                gp.deleteAID(loadcap.getPackageAID(), true);
                            }
                        }
                    }
                    for (CAPFile loadcap : caps) {
                        if (isVerbose) {
                            loadcap.dump(System.out);
                        }
                        loadCAP(args, gp, loadcap);
                    }
                }

                // --put-key <keyfile.pem or hex> or --replace-key <keyfile.pem or hex>
                // Load a public key or a plaintext symmetric key (for DAP or DM purposes)
                if (args.has(OPT_PUT_KEY) || args.has(OPT_REPLACE_KEY)) {
                    final Key kv = args.has(OPT_PUT_KEY) ? args.valueOf(OPT_PUT_KEY) : args.valueOf(OPT_REPLACE_KEY);
                    final int keyVersion = args.valueOf(OPT_NEW_KEY_VERSION);
                    if (keyVersion < 0x01 || keyVersion > 0x7F) {
                        System.err.println("Invalid key version: " + GPUtils.intString(keyVersion) + ", some possible values:");
                        System.err.println(GPKeyInfo.keyVersionPurposes.entrySet().stream().map(e -> String.format("%s - %s", GPUtils.intString(e.getKey()), e.getValue())).collect(Collectors.joining("\n")));
                        throw new IllegalArgumentException("Invalid key version: " + GPUtils.intString(keyVersion));
                    }

                    // Check for presence (thus replace)
                    // WORKAROUND: some cards reject the command if actually trying to replace existing key.
                    // List<GPKeyInfo> current = gp.getKeyInfoTemplate();
                    // boolean replace = current.stream().filter(p -> p.getVersion() == keyVersion).count() == 1 || args.has(OPT_REPLACE_KEY);
                    boolean replace = args.has(OPT_REPLACE_KEY);
                    if (kv.getPublic().isPresent()) {
                        gp.putKey(kv.getPublic().get(), keyVersion, replace);
                    } else if (kv.getSymmetric().isPresent()) {
                        java.security.Key k = kv.getSymmetric().get();
                        gp.putKey(k, keyVersion, replace);
                    } else {
                        throw new IllegalArgumentException("Only public and symmetric keys are supported for put-key");
                    }
                }

                if (args.has(OPT_INSTALL_ONLY)) {
                    GPRegistry registry = gp.getRegistry();
                    InstallDefinition dwim = InstallDefinition.fromOptions(registry, args);
                }

                // --install <applet.cap> (--applet <aid> --create <aid> --privs <privs> --params <params>)
                if (args.has(OPT_INSTALL)) {
                    if (!args.has(OPT_FORCE) && !args.has(OPT_SAD))
                        warnIfNoDelegatedManagement(gp);


                    CAPFile capfile = CAPFile.fromFile(Path.of(args.valueOf(OPT_INSTALL)));

                    if (args.has(OPT_VERBOSE)) {
                        capfile.dump(System.out);
                    }

                    GPRegistry reg = gp.getRegistry();

                    // Remove existing load file if needed
                    if (args.has(OPT_FORCE) && reg.allPackageAIDs().contains(capfile.getPackageAID())) {
                        gp.deleteAID(capfile.getPackageAID(), true);
                    }

                    // Get install parameters
                    final AID appaid;
                    final AID instanceaid;
                    if (capfile.getAppletAIDs().isEmpty()) {
                        throw new IllegalArgumentException("CAP file has no applets!");
                    } else if (capfile.getAppletAIDs().size() > 1) {
                        if (args.has(OPT_APPLET)) {
                            appaid = args.valueOf(OPT_APPLET);
                        } else {
                            throw new IllegalArgumentException("CAP contains more than one applet, specify the right one with --" + OPT_APPLET);
                        }
                    } else {
                        appaid = capfile.getAppletAIDs().get(0);
                    }

                    // override instance AID
                    instanceaid = optional(args, OPT_CREATE).orElse(appaid);

                    Set<Privilege> privs = getPrivileges(args);

                    // Load CAP
                    loadCAP(args, gp, capfile);

                    // Remove existing default app FIXME: document. this might be non-obvious
                    if (args.has(OPT_FORCE) && (reg.getDefaultSelectedAID().isPresent() && privs.contains(Privilege.CardReset))) {
                        System.err.println("NOTE: Force-removing current default selected applet instance: " + reg.getDefaultSelectedAID().get());
                        gp.deleteAID(reg.getDefaultSelectedAID().get(), false);
                    }

                    // warn
                    if (gp.getRegistry().allAppletAIDs().contains(instanceaid)) {
                        System.err.println("WARNING: Applet " + instanceaid + " already present on card");
                        if (args.has(OPT_FORCE)) {
                            gp.deleteAID(instanceaid, false);
                        }
                    }

                    // Parameters
                    byte[] params = args.has(OPT_PARAMS) ? args.valueOf(OPT_PARAMS).value() : new byte[0];

                    // shoot
                    gp.installAndMakeSelectable(capfile.getPackageAID(), appaid, instanceaid, privs, params);
                }


                // --create <aid> (--applet <aid> --package <aid> or --cap <cap>)
                if (args.has(OPT_CREATE) && !args.has(OPT_INSTALL)) {
                    if (!args.has(OPT_FORCE) && !args.has(OPT_SAD))
                        warnIfNoDelegatedManagement(gp);
                    AID packageAID = null;
                    AID appletAID = null;

                    // Load AID-s from cap if present
                    if (cap != null) {
                        packageAID = cap.getPackageAID();

                        if (cap.getAppletAIDs().size() > 1 && !args.has(OPT_APPLET)) {
                            throw new IllegalArgumentException("There should be only one applet in CAP. Use --" + OPT_APPLET + " to specify one of " + cap.getAppletAIDs());
                        }
                        appletAID = cap.getAppletAIDs().get(0);
                    }

                    // override
                    if (args.has(OPT_PACKAGE)) {
                        packageAID = args.valueOf(OPT_PACKAGE);
                    }
                    if (args.has(OPT_APPLET)) {
                        appletAID = args.valueOf(OPT_APPLET);
                    }

                    // check
                    if (packageAID == null || appletAID == null)
                        throw new IllegalArgumentException("Need --" + OPT_PACKAGE + " and --" + OPT_APPLET + " or --" + OPT_CAP);

                    AID instanceAID = args.valueOf(OPT_CREATE);

                    // warn
                    if (gp.getRegistry().allAIDs().contains(appletAID)) {
                        System.err.println("WARNING: Applet " + appletAID + " already present on card");
                    }

                    // Privileges
                    Set<Privilege> privs = getPrivileges(args);

                    // Parameters
                    byte[] params = optional(args, OPT_PARAMS).map(HexBytes::value).orElse(new byte[0]);

                    // shoot
                    gp.installAndMakeSelectable(packageAID, appletAID, instanceAID, privs, params);
                }

                // --domain <AID>
                if (args.has(OPT_DOMAIN)) {
                    // Validate parameters
                    BerTlvParser tlvparser = new BerTlvParser();
                    BerTlvs parameters = null;

                    byte[] params;
                    // If parameters given by user
                    if (args.has(OPT_PARAMS)) {
                        params = args.valueOf(OPT_PARAMS).value();
                        // Try to parse
                        try {
                            parameters = tlvparser.parse(params); // this throws
                        } catch (Exception e) {
                            // and fail if what is given is not TLV that we can modify.
                            if (args.has(OPT_ALLOW_FROM) || args.has(OPT_ALLOW_TO))
                                throw new IllegalArgumentException(OPT_ALLOW_FROM + " and " + OPT_ALLOW_TO + " not available, could not parse parameters: " + HexUtils.bin2hex(params));
                            // If we don't need to modify parameters, just give a handy warning
                            System.err.println("Warning: could not parse parameters as TLV: " + HexUtils.bin2hex(params));
                        }
                    } else {
                        params = new byte[0];
                        // This results in empty non-null parameters
                        parameters = tlvparser.parse(params);
                    }

                    // Default AID-s
                    final AID packageAID;
                    final AID appletAID;

                    // Override if necessary
                    if (args.has(OPT_PACKAGE) && args.has(OPT_APPLET)) {
                        packageAID = args.valueOf(OPT_PACKAGE);
                        appletAID = args.valueOf(OPT_APPLET);
                    } else {
                        // But query registry for defaults. Default to "new"
                        packageAID = gp.getRegistry().allPackageAIDs().contains(new AID("A0000000035350")) ? new AID("A0000000035350") : new AID("A0000001515350");
                        appletAID = gp.getRegistry().allPackageAIDs().contains(new AID("A0000000035350")) ? new AID("A000000003535041") : new AID("A000000151535041");
                        verbose("Note: using detected default AID-s for SSD instantiation: " + appletAID + " from " + packageAID);
                    }
                    AID instanceAID = args.valueOf(OPT_DOMAIN);

                    // Extra privileges
                    Set<Privilege> privs = getPrivileges(args);
                    privs.add(Privilege.SecurityDomain);

                    // By default same SCP as current
                    if (!args.has(OPT_SAD) && !gp.getProfile().oldStyleSSDParameters()) {
                        if (parameters != null && parameters.find(new BerTag(0x81)) == null) {
                            params = GPUtils.concatenate(params, new byte[]{(byte) 0x81, 0x02, gp.getSecureChannel().scp.getValue(), (byte) gp.getSecureChannel().i});
                        } else {
                            System.err.println("Notice: 0x81 (secure channel) already in parameters or no parameters");
                        }
                    }

                    // Extradition rules
                    if (args.has(OPT_ALLOW_TO)) {
                        if (parameters != null)
                            if (parameters.find(new BerTag(0x82)) == null) {
                                params = GPUtils.concatenate(params, new byte[]{(byte) 0x82, 0x02, 0x20, 0x20});
                            } else {
                                System.err.println("Warning: 0x82 already in parameters, " + OPT_ALLOW_TO + " not applied");
                            }
                    }

                    if (args.has(OPT_ALLOW_FROM)) {
                        if (parameters != null) {
                            if (parameters.find(new BerTag(0x87)) == null) {
                                params = GPUtils.concatenate(params, new byte[]{(byte) 0x87, 0x02, 0x20, 0x20});
                            } else {
                                System.err.println("Warning: 0x87 already in parameters, " + OPT_ALLOW_FROM + " not applied");
                            }
                        }
                    }

                    // Old style actually only allows one parameter, the 45
                    if (args.has(OPT_ALLOW_TO) && gp.getProfile().oldStyleSSDParameters()) {
                        params = HexUtils.hex2bin("C90145");
                    }

                    if (parameters != null || args.has(OPT_ALLOW_TO) || args.has(OPT_ALLOW_FROM)) {
                        verbose(String.format("Final parameters: %s", HexUtils.bin2hex(params)));
                    }
                    // shoot
                    gp.installAndMakeSelectable(packageAID, appletAID, instanceAID, privs, params);
                }

                // --move <AID>
                if (args.has(OPT_MOVE)) {
                    if (!args.has(OPT_FORCE) && !args.has(OPT_SAD))
                        warnIfNoDelegatedManagement(gp);
                    AID what = args.valueOf(OPT_MOVE);
                    AID to = args.valueOf(OPT_TO);
                    gp.extradite(what, to);
                }

                // --store-data <XX>
                // This will split the data, if necessary
                if (args.has(OPT_STORE_DATA)) {
                    List<byte[]> blobs = args.valuesOf(OPT_STORE_DATA).stream().map(HexBytes::value).collect(Collectors.toList());
                    for (byte[] blob : blobs) {
                        if (args.has(OPT_APPLET)) {
                            gp.personalize(args.valueOf(OPT_APPLET), blob, 0x01);
                        } else {
                            gp.storeData(blob, 0x1);
                        }
                    }
                }

                // --store-data-chunk
                // This will collect the chunks and send them one by one
                if (args.has(OPT_STORE_DATA_CHUNK)) {
                    List<byte[]> blobs = args.valuesOf(OPT_STORE_DATA_CHUNK).stream().map(HexBytes::value).collect(Collectors.toList());
                    if (args.has(OPT_APPLET)) {
                        gp.personalize(args.valueOf(OPT_APPLET), blobs, 0x01);
                    } else {
                        gp.storeData(blobs, 0x1);
                    }
                }

                // --store-dgi-file <file>
                // Will collect DGI-s and send them one by one, applying necessary encryption on the fly.
                if (args.has(OPT_STORE_DGI_FILE)) {
                    var oracle = paddingOracle(args);
                    var blocks = DGI.parse(args.valueOf(OPT_STORE_DGI_FILE).toPath(), oracle);
                    for (int i = 0; i < blocks.size(); i++) {
                        var dgi = blocks.get(i);
                        // Mark as DGI and encrypted if needed TODO: profile...
                        int p1 = dgi.type() == DGI.Type.PLAINTEXT ? 0x00 : 0x60; // NOTE: there NO no format indicator
                        // Construct the payload WTF is this scp code, need refactor
                        var payload = dgi.type() == DGI.Type.PADDING ? GPCrypto.pad80(dgi.value(), gp.getSecureChannel().scp == SCP03 ? 16 : 8) : dgi.value(); // FIXME: padding fixed for des.
                        if (dgi.type() != DGI.Type.PLAINTEXT) payload = gp.encryptDEK(payload);
                        payload = GPUtils.concatenate(dgi.tag(), DGI.length(payload.length), payload);
                        // Handle last block
                        p1 = (i == (blocks.size() - 1)) ? p1 | 0x80 : p1 & 0x7F;
                        CommandAPDU store = new CommandAPDU(GPSession.CLA_GP, GPSession.INS_STORE_DATA, p1, i, payload, 256);
                        GPException.check(gp.transmit(store), "STORE DATA failed");
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
                // --initialize-card
                if (args.has(OPT_INITIALIZE_CARD)) {
                    gp.setCardStatus(GPData.initializedStatus);
                }
                // --secure-card
                if (args.has(OPT_SECURE_CARD)) {
                    // Skip INITIALIZED
                    GPRegistryEntry isd = gp.getRegistry().getISD().orElseThrow(() -> new GPException("ISD not present, are you in a subtree?"));
                    if (isd.getLifeCycle() != GPData.initializedStatus && args.has(OPT_FORCE)) {
                        System.out.println("Note: forcing status to INITIALIZED");
                        gp.setCardStatus(GPData.initializedStatus);
                    }
                    gp.setCardStatus(GPData.securedStatus);
                }

                // --lock-applet <aid>
                if (args.has(OPT_LOCK_APPLET)) {
                    gp.lockUnlockApplet(args.valueOf(OPT_LOCK_APPLET), true);
                }

                // --unlock-applet <AID>
                if (args.has(OPT_UNLOCK_APPLET)) {
                    gp.lockUnlockApplet(args.valueOf(OPT_UNLOCK_APPLET), false);
                }

                // --list
                if (args.has(OPT_LIST)) {
                    GPCommands.listRegistry(gp.getRegistry(), System.out, args.has(OPT_VERBOSE));
                }

                // --delete-key
                if (args.has(OPT_DELETE_KEY)) {
                    int keyver = args.valueOf(OPT_DELETE_KEY);
                    System.out.println("Deleting key " + GPUtils.intString(keyver));
                    gp.deleteKey(keyver, null);
                }


                // --lock
                if (args.has(OPT_LOCK) || args.has(OPT_LOCK_ENC) || args.has(OPT_LOCK_MAC) || args.has(OPT_LOCK_DEK)) {
                    final GPCardKeys newKeys;
                    // By default we try to change an existing key
                    boolean replace = true;

                    // Get new key values
                    Optional<GPCardKeys> lockKey = keyFromPlugin(args.valueOf(OPT_LOCK));

                    String kdf = PlaintextKeys.kdf_templates.getOrDefault(args.valueOf(OPT_LOCK_KDF), args.valueOf(OPT_LOCK_KDF));
                    // From provider
                    newKeys = lockKey.
                            orElseGet(() -> PlaintextKeys.fromBytes(args.valueOf(OPT_LOCK_ENC).value(), args.valueOf(OPT_LOCK_MAC).value(), args.valueOf(OPT_LOCK_DEK).value(), HexBytes.v(args.valueOf(OPT_LOCK)).v(), kdf, null, args.valueOf(OPT_NEW_KEY_VERSION)).
                                    orElseThrow(() -> new IllegalArgumentException("Can not lock without keys :)")));

                    if (newKeys instanceof PlaintextKeys) {
                        // Adjust the mode and version with plaintext keys
                        PlaintextKeys pk = (PlaintextKeys) newKeys;
                        List<GPKeyInfo> current = gp.getKeyInfoTemplate();
                        // By default use key version 1
                        final int keyver;
                        if (args.has(OPT_NEW_KEY_VERSION)) {
                            keyver = args.valueOf(OPT_NEW_KEY_VERSION);
                            // Key version is indicated, check if already present on card
                            if (current.stream().noneMatch(e -> (e.getVersion() == keyver)) || gp.getScpKeyVersion() == 255) {
                                replace = false;
                            }
                        } else {
                            if (current.size() == 0 || gp.getScpKeyVersion() == 255) {
                                keyver = 1;
                                replace = false;
                            } else {
                                keyver = gp.getScpKeyVersion();
                            }
                        }
                        pk.setVersion(keyver);
                    }

                    // Diversify new keys
                    int keyver = newKeys.getKeyInfo().getVersion();
                    verbose("Keyset version: " + keyver);

                    // Only SCP02 via SCP03 should be possible, but cards vary
                    byte[] kdd = newKeys.getKDD().orElseGet(() -> keys.getKDD().get());

                    verbose("Looking at key version for diversification method");
                    if (keyver >= 0x10 && keyver <= 0x1F)
                        newKeys.diversify(SCP01, kdd);
                    else if (keyver >= 0x20 && keyver <= 0x2F)
                        newKeys.diversify(SCP02, kdd);
                    else if (keyver >= 0x30 && keyver <= 0x3F)
                        newKeys.diversify(SCP03, kdd);
                    else
                        newKeys.diversify(gp.getSecureChannel().scp, kdd);

                    gp.putKeys(newKeys, replace);

                    if (args.has(OPT_LOCK) && newKeys instanceof PlaintextKeys) {
                        PlaintextKeys pk = (PlaintextKeys) newKeys;
                        if (pk.getMasterKey().isPresent())
                            System.out.println(gp.getAID() + " locked with: " + HexUtils.bin2hex(pk.getMasterKey().get()));
                        if (pk.getTemplate() != null)
                            System.out.println("Keys were diversified with " + pk.getTemplate() + " and " + HexUtils.bin2hex(kdd));
                        System.out.println("Write this down, DO NOT FORGET/LOSE IT!");
                    } else {
                        System.out.println("Card locked with new keys.");
                        System.out.println("Write them down, DO NOT FORGET/LOSE THEM!");
                    }
                }

                // --make-default <aid>
                if (args.has(OPT_MAKE_DEFAULT)) {
                    gp.makeDefaultSelected(args.valueOf(OPT_MAKE_DEFAULT));
                }

                // --rename-isd
                if (args.has(OPT_RENAME_ISD)) {
                    gp.renameISD(args.valueOf(OPT_RENAME_ISD));
                }

                // --set-pre-perso
                if (args.has(OPT_SET_PRE_PERSO)) {
                    byte[] payload = args.valueOf(OPT_SET_PRE_PERSO).value();
                    if (args.has(OPT_TODAY)) {
                        System.arraycopy(GPData.CPLC.today(), 0, payload, 2, 2);
                    }
                    GPCommands.setPrePerso(gp, payload);
                }

                // --set-perso
                if (args.has(OPT_SET_PERSO)) {
                    byte[] payload = args.valueOf(OPT_SET_PERSO).value();
                    if (args.has(OPT_TODAY)) {
                        System.arraycopy(GPData.CPLC.today(), 0, payload, 2, 2);
                    }
                    GPCommands.setPerso(gp, payload);
                }
            }
            return 0;
        } catch (IOException e) {
            System.err.println("ERROR: " + e.getMessage());
            if (isTrace)
                e.printStackTrace();
        } catch (ReceiptVerifier.ReceiptVerificationException e) {
            /// XXX: refactor
            System.err.println("WARNING: Operation completed, but receipt verification failed");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
        // Other exceptions escape. fin.
        return 1;
    }

    private void warnIfNoDelegatedManagement(GPSession session) throws IOException {
        if (session.getCurrentDomain().hasPrivilege(Privilege.DelegatedManagement) && !session.delegatedManagementEnabled()) {
            System.err.println("# Warning: specify delegated management key or token with --dm-key/--dm-token");
        }
    }


    private static Optional<GPCardKeys> keyFromPlugin(String spec) {
        try {
            ServiceLoader<CardKeysProvider> sl = ServiceLoader.load(CardKeysProvider.class, GPTool.class.getClassLoader());
            List<CardKeysProvider> list = new ArrayList<>();
            sl.iterator().forEachRemaining(list::add);
            return list.stream().map(e -> e.getCardKeys(spec)).filter(Optional::isPresent).map(Optional::get).findFirst();
        } catch (ServiceConfigurationError e) {
            System.err.println("Could not load key provider: " + e.getMessage());
        }
        return Optional.empty();
    }


    static Predicate<Privilege> dapPrivileges = e -> e == Privilege.MandatedDAPVerification || e == Privilege.DAPVerification;
    static Predicate<GPRegistryEntry> dapDomainFilter = e -> e.hasPrivilege(Privilege.MandatedDAPVerification) || e.hasPrivilege(Privilege.DAPVerification);

    // Extract parameters and call GPCommands.load()
    private static void loadCAP(OptionSet args, GPSession gp, CAPFile capFile) throws GPException, IOException {
        try {
            AID to = optional(args, OPT_TO).orElse(gp.getAID());
            GPRegistryEntry targetDomain = gp.getRegistry().getDomain(to).orElseThrow(() -> new IllegalArgumentException("Target domain does not exist: " + to));
            GPData.LFDBH lfdbh = args.has(OPT_SHA256) ? GPData.LFDBH.SHA256 : (args.has(OPT_HASH) ? args.valueOf(OPT_HASH) : null);

            // Automatic DAP domain discovery
            AID dapAid = null;
            Optional<GPRegistryEntry> dapDomain = gp.getRegistry().allDomains().stream().filter(dapDomainFilter).findFirst();
            if (dapDomain.isPresent()) {
                GPRegistryEntry entry = dapDomain.get();
                String privs = entry.getPrivileges().stream().filter(dapPrivileges).map(Privilege::toString).collect(Collectors.joining(", "));
                System.out.println("# Found DAP domain: " + entry.getAID() + " (" + privs + "); override with --" + OPT_DAP_DOMAIN);
                dapAid = entry.getAID();
            }

            // Validate DAP override
            if (args.has(OPT_DAP_DOMAIN)) {
                dapAid = args.valueOf(OPT_DAP_DOMAIN);
                AID finalDapAid = dapAid;
                GPRegistryEntry dapTarget = gp.getRegistry().getDomain(dapAid).orElseThrow(() -> new IllegalArgumentException("DAP domain does not exist: " + finalDapAid));
                if (!(dapTarget.hasPrivilege(Privilege.DAPVerification) || dapTarget.hasPrivilege(Privilege.MandatedDAPVerification))) {
                    String message = "Specified DAP domain does not have (Mandated)DAPVerification privilege: " + dapAid;
                    if (args.has(OPT_FORCE)) {
                        System.err.println("Warning: " + message);
                    } else {
                        throw new IllegalArgumentException(message);
                    }
                }
            }

            // Target has DAP, Mandated DAP is present, or manual DAP AID given
            boolean dapRequired = targetDomain.hasPrivilege(Privilege.DAPVerification)
                    || gp.getRegistry().allDomains().stream().anyMatch(e -> e.hasPrivilege(Privilege.MandatedDAPVerification))
                    || args.has(OPT_DAP_DOMAIN);

            final byte[] signature;
            if (dapRequired) {
                if (args.has(OPT_DAP_SIGNATURE)) {
                    signature = args.valueOf(OPT_DAP_SIGNATURE).value();
                } else if (args.has(OPT_DAP_KEY)) {
                    Key dapKey = args.valueOf(OPT_DAP_KEY);
                    if (dapKey.getPrivate().isEmpty()) {
                        throw new IllegalArgumentException("Invalid DAP key: " + dapKey);
                    }
                    signature = DAPSigner.sign(capFile, dapKey.getPrivate().get(), Optional.ofNullable(lfdbh).orElse(GPData.LFDBH.SHA256));
                } else {
                    // TODO: have some xml/zip parsers for ease of use like existing capfile (but deprecate that)
                    if (!args.has(OPT_FORCE)) {
                        throw new IllegalArgumentException("Need DAP signature!");
                    } else {
                        signature = null;
                    }
                }
            } else {
                signature = null;
            }

            // If/when to include lfdbh
            if (targetDomain.hasPrivilege(Privilege.DelegatedManagement) || dapRequired || lfdbh != null) {
                lfdbh = Optional.ofNullable(lfdbh).orElse(GPData.LFDBH.SHA256);
            }
            gp.loadCapFile(capFile, to, dapAid, signature, lfdbh);

            System.out.printf("%s loaded: %s %s%n", capFile.getFile().map(Path::toString).orElse("CAP"), capFile.getPackageName(), capFile.getPackageAID());
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
        } catch (GeneralSecurityException e) {
            throw new GPException("Failed to generate DAP signature: " + e.getMessage(), e);
        }
    }

    // Contains "what" to install
    static class InstallDefinition {
        final CAPFile cap;
        final AID pkg;
        final AID applet;
        final AID instance;

        private InstallDefinition(CAPFile cap, AID pkg, AID applet, AID instance) {
            this.cap = cap;
            this.pkg = pkg;
            this.applet = applet;
            this.instance = instance;
        }

        static InstallDefinition fromOptions(GPRegistry registry, OptionSet args) throws IOException {
            final AID applet;
            final CAPFile cap;
            final AID pkg;
            final AID instance;

            // One must be present, jopt-simple makes them mutually exclusive
            String pathOrAid = optional(args, OPT_INSTALL_ONLY).orElse(args.valueOf(OPT_INSTALL));
            Path p = Paths.get(pathOrAid);

            // --install refers to a file or --cap given
            if (Files.exists(p) || args.has(OPT_CAP)) {
                // Not possible to have both
                if (Files.exists(p) && args.has(OPT_CAP))
                    throw new IllegalArgumentException("Can't have --cap and --install(-only) refer to a capfile");

                if (args.has(OPT_CAP)) {
                    p = args.valueOf(OPT_CAP).toPath();
                }
                // Load CAP file
                cap = CAPFile.fromFile(p);

                // PKG comes from CAP file
                pkg = cap.getPackageAID();
                // TODO: gp -install <lib.cap> could still behave like -load <lib.cap>
                if (cap.getAppletAIDs().size() == 0) {
                    throw new IllegalArgumentException("Missing UX: load library capfiles with --load");
                } else if (cap.getAppletAIDs().size() == 1) {
                    // If argument given, it must match capfile
                    if (args.has(OPT_APPLET) && !args.valueOf(OPT_APPLET).equals(cap.getAppletAIDs().get(0))) {
                        throw new IllegalArgumentException(String.format("Capfile %s does not contain applet %s (has %s)", p, args.valueOf(OPT_APPLET), cap.getAppletAIDs()));
                    }
                    applet = cap.getAppletAIDs().get(0);
                } else {
                    // --applet MUST be given (or default name is searched for)
                    AID candidate = optional(args, OPT_APPLET).orElseThrow(() -> new IllegalArgumentException("Specify applet tp install with --applet"));
                    if (!cap.getAppletAIDs().contains(candidate)) {
                        throw new IllegalArgumentException(String.format("Specify applet to install with --applet (has %s)", cap.getAppletAIDs()));
                    }
                    applet = candidate;
                }
                // When --install refers a file, the existing name will be used
                instance = applet;
            } else {
                // Instance AID is explicit. Possibly load  package AID
                instance = AID.fromString(pathOrAid);
                cap = null;
                AID searchFor = optional(args, OPT_APPLET).orElse(instance);

                // Do some magic
                if (args.has(OPT_PACKAGE)) {
                    pkg = args.valueOf(OPT_PACKAGE);
                } else {
                    // Search for existing registry either for explicit applet or applet-with-same-name-as-instance
                    pkg = registry.byModule(searchFor).map(GPRegistryEntry::getAID).orElseThrow(() -> new IllegalArgumentException("Specify applet to load with --applet"));
                }
                // Applet AID is either --applet or instance if not given
                applet = searchFor;
            }

            return new InstallDefinition(cap, pkg, applet, instance);
        }
    }

    // NOTE: Integer is used because byte[] is not good for a set.
    static List<Integer> split(String s) {
        // remove whitespace and "0x" instances
        s = s.replaceAll("\\s+", "").replaceAll("0[xX]", "");

        // If longer than 4 and contains comma - try to parse as list
        if (s.contains(",") && s.length() > 4) {
            String[] parts = s.split(",");
            List<Integer> result = new ArrayList<>();

            for (String part : parts) {
                result.add(hex2int(part));
            }

            return result;
        } else {
            return Collections.singletonList(hex2int(s));
        }
    }

    static int hex2int(String s) {
        try {
            int value = Integer.parseInt(s, 16);
            if (value < 0x0000 || value > 0xFFFF) {
                throw new IllegalArgumentException("Value out of range (0x0000-0xFFFF): 0x" + Integer.toHexString(value));
            }
            return value;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid hex: " + s);
        }
    }

    // Create a small oracle that knows how to handle padding for different DGI-s
    private static Function<byte[], DGI.Type> paddingOracle(OptionSet args) {
        var padded = args.valuesOf(OPT_DGI_PADDED).stream().flatMap(s -> GPTool.split(s).stream()).collect(Collectors.toSet());
        var unpadded = args.valuesOf(OPT_DGI_UNPADDED).stream().flatMap(s -> GPTool.split(s).stream()).collect(Collectors.toSet());

        return s -> {
            var k = ((s[0] & 0xFF) << 8) | (s[1] & 0xFF);
            if (padded.contains(k)) {
                return DGI.Type.PADDING;
            } else if (unpadded.contains(k)) {
                return DGI.Type.NOPADDING;
            } else {
                return DGI.Type.PLAINTEXT;
            }
        };
    }

    private static EnumSet<Privilege> getPrivileges(OptionSet args) {
        EnumSet<Privilege> privs = EnumSet.noneOf(Privilege.class);
        if (args.has(OPT_PRIVS)) {
            for (String p : args.valuesOf(OPT_PRIVS))
                for (String s : p.split(","))
                    privs.add(Privilege.lookup(s.trim()).orElseThrow(() -> new IllegalArgumentException("Unknown privilege: " + s.trim() + "\nValid values are: " + Arrays.stream(Privilege.values()).map(Enum::toString).collect(Collectors.joining(", ")))));
        }
        return privs;
    }

    private static List<CAPFile> getCapFileList(OptionSet args, OptionSpec<File> arg) {
        return args.valuesOf(arg).stream().map(File::toPath).map(e -> {
            try {
                return CAPFile.fromFile(e);
            } catch (IOException x) {
                throw new IllegalArgumentException("Could not read CAP: " + x.getMessage());
            }
        }).collect(Collectors.toList());
    }

    private static boolean needsAuthentication(OptionSet args) {
        OptionSpec<?>[] yes = new OptionSpec<?>[]{OPT_CONNECT, OPT_LIST, OPT_LOAD, OPT_INSTALL, OPT_INSTALL_ONLY, OPT_DELETE, OPT_DELETE_KEY, OPT_CREATE,
                OPT_LOCK, OPT_LOCK_ENC, OPT_LOCK_MAC, OPT_LOCK_DEK, OPT_MAKE_DEFAULT,
                OPT_UNINSTALL, OPT_SECURE_APDU, OPT_DOMAIN, OPT_LOCK_CARD, OPT_UNLOCK_CARD, OPT_LOCK_APPLET, OPT_UNLOCK_APPLET,
                OPT_STORE_DATA, OPT_STORE_DATA_CHUNK, OPT_INITIALIZE_CARD, OPT_SECURE_CARD, OPT_RENAME_ISD, OPT_SET_PERSO, OPT_SET_PRE_PERSO, OPT_MOVE,
                OPT_PUT_KEY, OPT_REPLACE_KEY, OPT_STORE_DGI_FILE};

        return Arrays.stream(yes).anyMatch(args::has);
    }

    private void verbose(String s) {
        if (isVerbose) {
            System.out.println("# " + s);
        }
    }
}
