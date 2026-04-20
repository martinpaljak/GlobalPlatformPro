/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-present Martin Paljak, martin@martinpaljak.net
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
package pro.javacard.gp.ng;

import apdu4j.apdulette.Cookbook;
import apdu4j.apdulette.Recipe;
import apdu4j.apdulette.Chef;
import apdu4j.core.*;
import apdu4j.prefs.Preference;
import apdu4j.prefs.Preferences;
import apdu4j.pcsc.NoMatchingReaderException;
import apdu4j.pcsc.ReaderSelector;
import apdu4j.pcsc.Readers;
import pro.javacard.gp.ToolExtension;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.*;
import pro.javacard.gp.GPSession.APDUMode;
import pro.javacard.gp.emv.DGIData;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVParseException;
import pro.javacard.tlv.Tag;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;


// Does the CLI parameter parsing and associated execution
public final class GPToolNG extends GPCommandLineInterface implements ToolExtension {
    // NOTE: can't have a static logger here, as it is set up based on args and env. This class should only use stdout/stderr.

    private static boolean isTrace = false;

    static final String ENV_GP_AID = "GP_AID";
    static final String ENV_GP_READER = "GP_READER";
    static final String ENV_GP_READER_IGNORE = "GP_READER_IGNORE";
    static final Preference<String> READER_PREF = Preference.parameter("gp.reader", String.class, false);
    static final Preference<String> READER_IGNORE_PREF = Preference.parameter("gp.reader.ignore", String.class, false);
    static final String ENV_GP_TRACE = "GP_TRACE";
    static final String ENV_GP_PCSC_RESET = "GP_PCSC_RESET";
    static final String ENV_GP_PCSC_EXCLUSIVE = "GP_PCSC_EXCLUSIVE";
    static final String ENV_GP_PCSC_TRANSACT = "GP_PCSC_TRANSACT";

    // Pre/post auth recipe plan
    record RecipePlan(List<Recipe<?>> preAuth, List<Recipe<?>> postAuth) {
    }

    // Bridge CLI options to Preferences via a declarative mapping.
    @SafeVarargs
    public static Preferences fromOptions(OptionSet args, Function<OptionSet, Preferences>... bindings) {
        var prefs = new Preferences();
        for (var binding : bindings) {
            prefs = prefs.merge(binding.apply(args));
        }
        return prefs;
    }

    // Direct: option value type matches preference type
    public static <T> Function<OptionSet, Preferences> bind(OptionSpec<T> opt, Preference.Default<T> pref) {
        return args -> args.has(opt) ? new Preferences().with(pref, args.valueOf(opt)) : new Preferences();
    }

    // With converter: option value type differs from preference type
    public static <T, V> Function<OptionSet, Preferences> bind(OptionSpec<T> opt, Preference.Default<V> pref, Function<T, V> fn) {
        return args -> args.has(opt) ? new Preferences().with(pref, fn.apply(args.valueOf(opt))) : new Preferences();
    }

    // Boolean flag: presence means true
    public static Function<OptionSet, Preferences> flag(OptionSpec<Void> opt, Preference.Default<Boolean> pref) {
        return args -> args.has(opt) ? new Preferences().with(pref, true) : new Preferences();
    }

    static void setupLogging(OptionSet args) {
        // Set up slf4j simple in a way that pleases us
        System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
        System.setProperty("org.slf4j.simpleLogger.levelInBrackets", "true");
        System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");

        if (args.has(OPT_VERBOSE)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info");
        }
        if (args.has(OPT_DEBUG) && args.has(OPT_VERBOSE)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        }
        if (args.has(OPT_DEBUG) && System.getenv().containsKey(ENV_GP_TRACE)) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
            isTrace = true;
        }
    }

    // Explicitly public, to not forget the need for apdu4j
    public GPToolNG() {
    }

    private static void showPreamble(String[] argv, OptionSet args) {
        // dump relevant environment and command line variables in verbose+ mode
        if (args.has(OPT_VERBOSE) || args.has(OPT_DEBUG) || args.has(OPT_INFO)) {
            var gpenv = System.getenv().entrySet().stream().filter(e -> e.getKey().startsWith("GP_")).map(e -> "%s=%s".formatted(e.getKey(), e.getValue())).collect(Collectors.toList());
            if (gpenv.size() > 0) {
                System.out.println("# " + String.join(" ", gpenv));
            }
            System.out.println("# gp " + String.join(" ", argv));
        }
        if (args.has(OPT_VERBOSE) || args.has(OPT_DEBUG) || args.has(OPT_INFO) || args.has(OPT_VERSION)) {
            var ver = Optional.ofNullable(GPToolNG.class.getPackage().getImplementationVersion()).orElse("development");
            var hash = selfhash();
            if (hash != null) {
                System.out.printf("SHA256 = %s%n", HexFormat.of().formatHex(hash));
            }
            System.out.printf("# GlobalPlatformPro NG %s%n", ver);
            System.out.printf("# Running on %s %s %s", System.getProperty("os.name"), System.getProperty("os.version"), System.getProperty("os.arch"));
            System.out.printf(", Java %s by %s%n", System.getProperty("java.version"), System.getProperty("java.vendor"));
        }
    }

    static byte[] selfhash() {
        var pd = GPToolNG.class.getProtectionDomain();
        if (pd != null && pd.getCodeSource() != null && pd.getCodeSource().getLocation() != null) {
            try {
                var location = pd.getCodeSource().getLocation();
                Path p = Paths.get(location.toURI());
                if (Files.isDirectory(p)) {
                    // probably development
                    return null;
                }
                return MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p));
            } catch (Exception e) {
                System.err.println("Could not verify integrity: " + e.getMessage());
            }
        }
        return null;
    }

    @Override
    public int run(String[] argv) {
        return execute(argv);
    }

    // Handle commands that don't need a card reader
    static OptionalInt handleCardless(OptionSet args) throws IOException {
        if (onlyHasArg(args, OPT_VERSION)) {
            return OptionalInt.of(0);
        }
        if (onlyHasArg(args, OPT_CAP)) {
            CAPFile.fromFile(args.valueOf(OPT_CAP).toPath()).dump(System.out);
            return OptionalInt.of(0);
        }
        return OptionalInt.empty();
    }

    // Resolve NG CardKeys from CLI options and environment
    static CardKeys resolveKeys(OptionSet args, Map<String, String> env) {
        CardKeys ngKeys;
        var ngKey = parseNGKeySpec(args.valueOf(OPT_KEY));
        if (ngKey.isPresent()) {
            ngKeys = ngKey.get();
        } else {
            Optional<PlaintextCardKeys> envKeys = PlaintextCardKeys.fromEnvironment();
            Optional<PlaintextCardKeys> cliKeys;
            if (args.has(OPT_KEY_ENC) && args.has(OPT_KEY_MAC) && args.has(OPT_KEY_DEK)) {
                cliKeys = Optional.of(PlaintextCardKeys.fromKeys(args.valueOf(OPT_KEY_ENC).v(), args.valueOf(OPT_KEY_MAC).v(), args.valueOf(OPT_KEY_DEK).v()));
            } else {
                cliKeys = Optional.empty();
            }
            if (envKeys.isPresent() && cliKeys.isPresent()) {
                System.err.println("# Warning: keys set on command line shadow environment!");
            } else if (envKeys.isEmpty() && cliKeys.isEmpty()) {
                if (args.has(OPT_SAD)) {
                    throw new IllegalArgumentException("no keys given");
                } else {
                    System.err.println("# Warning: no keys given, defaulting to " + HexUtils.bin2hex(PlaintextCardKeys.defaultKeyBytes()));
                }
            }
            ngKeys = cliKeys.or(() -> envKeys).orElse(PlaintextCardKeys.defaultKey());
        }
        if (ngKeys instanceof PlaintextCardKeys ngk) {
            if (args.has(OPT_KEY_KDF)) {
                ngKeys = ngk.withKdfTemplate(PlaintextCardKeys.KDF_TEMPLATES.getOrDefault(args.valueOf(OPT_KEY_KDF), args.valueOf(OPT_KEY_KDF)));
            }
            if (args.has(OPT_KEY_VERSION)) {
                ngKeys = ((PlaintextCardKeys) ngKeys).withVersion(args.valueOf(OPT_KEY_VERSION));
            }
        }
        return ngKeys;
    }

    // Resolve SCP mode from CLI options
    static EnumSet<APDUMode> resolveMode(OptionSet args) {
        if (args.has(OPT_SC_MODE)) {
            var mode = EnumSet.noneOf(APDUMode.class);
            mode.addAll(args.valuesOf(OPT_SC_MODE));
            return mode;
        }
        return EnumSet.of(APDUMode.MAC);
    }

    // Build CLI preferences from options
    static Preferences buildCliPrefs(OptionSet args) {
        var prefs = fromOptions(args, bind(OPT_BS, GlobalPlatformCookbook.BLOCK_SIZE), bind(OPT_HASH, GlobalPlatformCookbook.LOAD_HASH, h -> h.toString()), flag(OPT_S16, GlobalPlatformCookbook.FORCE_S16));

        // Profile
        if (args.has(OPT_PROFILE)) {
            var p = GlobalPlatformCookbook.PRESETS.get(args.valueOf(OPT_PROFILE));
            if (p != null) {
                prefs = prefs.merge(p);
            } else {
                System.err.printf("Unknown profile '%s', known profiles: %s%n", args.valueOf(OPT_PROFILE), String.join(", ", GlobalPlatformCookbook.PRESETS.keySet()));
            }
        }

        // DM tokenizer
        if (args.has(OPT_DM_KEY)) {
            var kv = args.valueOf(OPT_DM_KEY);
            if (kv.getPrivate().isPresent() && kv.getPrivate().get() instanceof RSAPrivateKey rsaKey) {
                prefs = prefs.with(GlobalPlatformCookbook.DM_TOKENIZER, DMTokenizer.forPrivateKey(rsaKey));
            } else if (kv.getSymmetric().isPresent() && kv.getSymmetric().get() instanceof SecretKey aesKey) {
                prefs = prefs.with(GlobalPlatformCookbook.DM_TOKENIZER, DMTokenizer.forAESKey(aesKey));
            } else {
                throw new IllegalArgumentException("Only RSA private or AES keys are supported for DM");
            }
        } else if (args.has(OPT_DM_TOKEN)) {
            prefs = prefs.with(GlobalPlatformCookbook.DM_TOKENIZER, DMTokenizer.forToken(args.valueOf(OPT_DM_TOKEN).value()));
        }

        // Receipt verifier
        if (args.has(OPT_RECEIPT_KEY)) {
            prefs = prefs.with(GlobalPlatformCookbook.RECEIPT_VERIFIER, new ReceiptVerifier.AESReceiptVerifier(args.valueOf(OPT_RECEIPT_KEY).v(), args.has(OPT_FORCE)));
        }

        return prefs;
    }

    // Build pre-auth and post-auth recipe lists from CLI flags
    static RecipePlan buildRecipes(OptionSet args, Map<String, String> env, CardKeys keys, CAPFile cap, Preferences cliPrefs) throws IOException {
        var preAuth = new ArrayList<Recipe<?>>();
        var postAuth = new ArrayList<Recipe<?>>();

        if (args.has(OPT_CONNECT)) {
            preAuth.add(GlobalPlatformCookbook.select_aid(args.valueOf(OPT_CONNECT).getBytes()));
        } else if (env.containsKey(ENV_GP_AID)) {
            preAuth.add(GlobalPlatformCookbook.select_aid(AID.fromString(env.get(ENV_GP_AID)).getBytes()));
        }

        if (args.has(OPT_INFO)) {
            preAuth.add(GlobalPlatformCookbook.discover(List.of()).consume(GPToolNG::printDiscovery));
        }

        if (args.has(OPT_APDU)) {
            AID target = null;
            if (args.has(OPT_APPLET)) {
                target = args.valueOf(OPT_APPLET);
            } else if (cap != null) {
                target = cap.getAppletAIDs().get(0);
            }
            if (target != null) {
                preAuth.add(GlobalPlatformCookbook.select_aid(target.getBytes()));
            }
            for (byte[] s : args.valuesOf(OPT_APDU).stream().map(APDUParsers::stringToAPDU).toList()) {
                preAuth.add(Cookbook.send(new CommandAPDU(s), Cookbook.any()).consume(APDUParsers::print_response));
            }
        }

        // Cleanup: delete content and keys
        if (args.has(OPT_DELETE)) {
            for (AID a : args.valuesOf(OPT_DELETE)) {
                postAuth.add(GlobalPlatformCookbook.delete_aid(a, args.has(OPT_FORCE)));
            }
        }

        if (args.has(OPT_UNINSTALL)) {
            for (File f : args.valuesOf(OPT_UNINSTALL)) {
                var uninstallCap = CAPFile.fromFile(f.toPath());
                postAuth.add(GlobalPlatformCookbook.delete_aid(uninstallCap.getPackageAID(), true));
            }
        }

        if (args.has(OPT_DELETE_KEY)) {
            postAuth.add(GlobalPlatformCookbook.delete_key(args.valueOf(OPT_DELETE_KEY), null));
        }

        // Load and install
        if (args.has(OPT_LOAD)) {
            for (File f : args.valuesOf(OPT_LOAD)) {
                var loadcap = CAPFile.fromFile(f.toPath());
                if (args.has(OPT_FORCE)) {
                    postAuth.add(GlobalPlatformCookbook.delete_aid(loadcap.getPackageAID(), true).recover(err -> Recipe.premade(err.response())));
                }
                postAuth.add(Cookbook.deferred(prefs -> {
                    var targetDomain = args.has(OPT_TO) ? args.valueOf(OPT_TO) : prefs.valueOf(GlobalPlatformCookbook.ISD_AID).orElse(new AID(GlobalPlatformCookbook.DEFAULT_ISD));
                    return GlobalPlatformCookbook.load_cap_file(loadcap, targetDomain);
                }));
            }
        }

        if (args.has(OPT_INSTALL)) {
            var capfile = CAPFile.fromFile(Path.of(args.valueOf(OPT_INSTALL)));
            // Resolve applet AID
            AID appaid;
            if (capfile.getAppletAIDs().isEmpty()) {
                throw new IllegalArgumentException("CAP file has no applets!");
            } else if (capfile.getAppletAIDs().size() > 1) {
                appaid = optional(args, OPT_APPLET).orElseThrow(() -> new IllegalArgumentException("CAP contains more than one applet, specify with --applet"));
            } else {
                appaid = capfile.getAppletAIDs().get(0);
            }
            var instanceaid = optional(args, OPT_CREATE).orElse(appaid);

            // Force-delete existing package
            if (args.has(OPT_FORCE)) {
                postAuth.add(GlobalPlatformCookbook.delete_aid(capfile.getPackageAID(), true).recover(err -> Recipe.premade(err.response())));
            }

            // Load
            postAuth.add(Cookbook.deferred(prefs -> {
                var targetDomain = args.has(OPT_TO) ? args.valueOf(OPT_TO) : prefs.valueOf(GlobalPlatformCookbook.ISD_AID).orElse(new AID(GlobalPlatformCookbook.DEFAULT_ISD));
                return GlobalPlatformCookbook.load_cap_file(capfile, targetDomain);
            }));

            // Force-delete existing instance
            if (args.has(OPT_FORCE)) {
                postAuth.add(GlobalPlatformCookbook.delete_aid(instanceaid, false).recover(err -> Recipe.premade(err.response())));
            }

            // Install
            var privs = getPrivilegesNG(args);
            var params = args.has(OPT_PARAMS) ? args.valueOf(OPT_PARAMS).value() : new byte[0];
            postAuth.add(GlobalPlatformCookbook.install_and_make_selectable(capfile.getPackageAID(), appaid, instanceaid, privs, params));
        }

        if (args.has(OPT_INSTALL_ONLY)) {
            var pathOrAid = args.valueOf(OPT_INSTALL_ONLY);
            var p = Path.of(pathOrAid);
            if (Files.exists(p) || args.has(OPT_CAP)) {
                var installCap = CAPFile.fromFile(args.has(OPT_CAP) ? args.valueOf(OPT_CAP).toPath() : p);
                var applet = optional(args, OPT_APPLET).orElse(installCap.getAppletAIDs().get(0));
                var instance = optional(args, OPT_CREATE).orElse(applet);
                var privs = getPrivilegesNG(args);
                var params = args.has(OPT_PARAMS) ? args.valueOf(OPT_PARAMS).value() : new byte[0];
                postAuth.add(GlobalPlatformCookbook.install_and_make_selectable(installCap.getPackageAID(), applet, instance, privs, params));
            } else {
                var instance = AID.fromString(pathOrAid);
                var applet = optional(args, OPT_APPLET).orElse(instance);
                var pkg = optional(args, OPT_PACKAGE).orElseThrow(() -> new IllegalArgumentException("Specify --package when --install-only is an AID"));
                var privs = getPrivilegesNG(args);
                var params = args.has(OPT_PARAMS) ? args.valueOf(OPT_PARAMS).value() : new byte[0];
                postAuth.add(GlobalPlatformCookbook.install_and_make_selectable(pkg, applet, instance, privs, params));
            }
        }

        if (args.has(OPT_CREATE) && !args.has(OPT_INSTALL)) {
            AID packageAID = null;
            AID appletAID = null;
            if (cap != null) {
                packageAID = cap.getPackageAID();
                appletAID = cap.getAppletAIDs().size() == 1 ? cap.getAppletAIDs().get(0) : null;
            }
            if (args.has(OPT_PACKAGE)) {
                packageAID = args.valueOf(OPT_PACKAGE);
            }
            if (args.has(OPT_APPLET)) {
                appletAID = args.valueOf(OPT_APPLET);
            }
            if (packageAID == null || appletAID == null) {
                throw new IllegalArgumentException("Need --package and --applet or --cap");
            }
            var instanceAID = args.valueOf(OPT_CREATE);
            var privs = getPrivilegesNG(args);
            var params = optional(args, OPT_PARAMS).map(HexBytes::value).orElse(new byte[0]);
            postAuth.add(GlobalPlatformCookbook.install_and_make_selectable(packageAID, appletAID, instanceAID, privs, params));
        }

        if (args.has(OPT_DOMAIN)) {
            AID packageAID;
            AID appletAID;
            if (args.has(OPT_PACKAGE) && args.has(OPT_APPLET)) {
                packageAID = args.valueOf(OPT_PACKAGE);
                appletAID = args.valueOf(OPT_APPLET);
            } else {
                packageAID = new AID("A0000001515350");
                appletAID = new AID("A000000151535041");
            }
            var instanceAID = args.valueOf(OPT_DOMAIN);
            var privs = getPrivilegesNG(args);
            privs.add(GPRegistryEntryNG.Privilege.SecurityDomain);

            var baseParams = optional(args, OPT_PARAMS).map(HexBytes::value).orElse(new byte[0]);
            var allowTo = args.has(OPT_ALLOW_TO);
            var allowFrom = args.has(OPT_ALLOW_FROM);
            var appendScp = !args.has(OPT_SAD);
            postAuth.add(Cookbook.deferred(prefs -> {
                var scpVersion = appendScp ? prefs.valueOf(GlobalPlatformCookbook.SCP_VERSION).orElse(null) : null;
                var params = domain_install_params(baseParams, scpVersion, allowTo, allowFrom);
                return GlobalPlatformCookbook.install_and_make_selectable(packageAID, appletAID, instanceAID, privs, params);
            }));
        }

        // Key management
        if (args.has(OPT_PUT_KEY) || args.has(OPT_REPLACE_KEY)) {
            PlaintextKey kv = args.has(OPT_PUT_KEY) ? args.valueOf(OPT_PUT_KEY) : args.valueOf(OPT_REPLACE_KEY);
            var keyVersion = args.valueOf(OPT_NEW_KEY_VERSION);
            if (keyVersion < 0x01 || keyVersion > 0x7F) {
                throw new IllegalArgumentException("Invalid key version: " + GPUtils.intString(keyVersion));
            }
            var replace = args.has(OPT_REPLACE_KEY);

            if (kv.getPublic().isPresent()) {
                postAuth.add(GlobalPlatformCookbook.put_public_key(kv.getPublic().get(), keyVersion, replace));
            } else if (kv.getSymmetric().isPresent()) {
                var sk = kv.getSymmetric().get();
                postAuth.add(GlobalPlatformCookbook.put_symmetric_key(keys, sk.getEncoded(), "AES".equals(sk.getAlgorithm()), keyVersion, replace));
            } else {
                throw new IllegalArgumentException("Only public and symmetric keys are supported for put-key");
            }
        }

        // Move and configure
        if (args.has(OPT_MOVE)) {
            postAuth.add(GlobalPlatformCookbook.extradite(args.valueOf(OPT_MOVE), args.valueOf(OPT_TO)));
        }

        if (args.has(OPT_MAKE_DEFAULT)) {
            postAuth.add(GlobalPlatformCookbook.make_default_selected(args.valueOf(OPT_MAKE_DEFAULT)));
        }

        // Personalization
        if (args.has(OPT_PERSONALIZE)) {
            postAuth.add(GlobalPlatformCookbook.install_for_personalization(args.valueOf(OPT_PERSONALIZE)));
        }

        if (args.has(OPT_STORE_DATA)) {
            if (!args.has(OPT_PERSONALIZE) && args.has(OPT_APPLET)) {
                postAuth.add(GlobalPlatformCookbook.install_for_personalization(args.valueOf(OPT_APPLET)));
            }
            for (byte[] blob : args.valuesOf(OPT_STORE_DATA).stream().map(HexBytes::value).toList()) {
                postAuth.add(GlobalPlatformCookbook.store_data_blob(blob, 0x01));
            }
        }

        if (args.has(OPT_STORE_DATA_CHUNK)) {
            if (!args.has(OPT_PERSONALIZE) && args.has(OPT_APPLET)) {
                postAuth.add(GlobalPlatformCookbook.install_for_personalization(args.valueOf(OPT_APPLET)));
            }
            var chunks = args.valuesOf(OPT_STORE_DATA_CHUNK).stream().map(HexBytes::value).toList();
            postAuth.add(GlobalPlatformCookbook.store_data_blocks(chunks, 0x01));
        }

        if (args.has(OPT_STORE_DATA_RAW)) {
            var commands = args.valuesOf(OPT_STORE_DATA_RAW).stream()
                    .map(APDUParsers::stringToAPDU)
                    .map(CommandAPDU::new)
                    .toList();
            postAuth.add(GlobalPlatformCookbook.store_data(commands));
        }

        if (args.has(OPT_STORE_DGI_FILE)) {
            var oracle = paddingOracle(args);
            var dgiBlocks = DGIData.parse(args.valueOf(OPT_STORE_DGI_FILE).toPath(), oracle);
            postAuth.add(GlobalPlatformCookbook.store_dgi(dgiBlocks, keys));
        }

        // CPLC personalization
        if (args.has(OPT_SET_PRE_PERSO)) {
            var payload = args.valueOf(OPT_SET_PRE_PERSO).value();
            if (args.has(OPT_TODAY)) {
                System.arraycopy(CPLC.today(), 0, payload, 2, 2);
            }
            postAuth.add(GlobalPlatformCookbook.set_pre_perso(payload));
        }
        if (args.has(OPT_SET_PERSO)) {
            var payload = args.valueOf(OPT_SET_PERSO).value();
            if (args.has(OPT_TODAY)) {
                System.arraycopy(CPLC.today(), 0, payload, 2, 2);
            }
            postAuth.add(GlobalPlatformCookbook.set_perso(payload));
        }

        // Secure APDU (arbitrary commands after structured operations)
        if (args.has(OPT_SECURE_APDU)) {
            for (byte[] s : args.valuesOf(OPT_SECURE_APDU).stream().map(APDUParsers::stringToAPDU).toList()) {
                postAuth.add(Cookbook.send(new CommandAPDU(s), Cookbook.any()).consume(APDUParsers::print_response));
            }
        }

        // Card lifecycle
        if (args.has(OPT_LOCK_CARD)) {
            postAuth.add(GlobalPlatformCookbook.set_card_status(GPRegistryEntryNG.ISDLifeCycle.CARD_LOCKED));
        }
        if (args.has(OPT_UNLOCK_CARD)) {
            postAuth.add(GlobalPlatformCookbook.set_card_status(GPRegistryEntryNG.ISDLifeCycle.SECURED));
        }
        if (args.has(OPT_INITIALIZE_CARD)) {
            postAuth.add(GlobalPlatformCookbook.set_card_status(GPRegistryEntryNG.ISDLifeCycle.INITIALIZED));
        }
        if (args.has(OPT_SECURE_CARD)) {
            if (args.has(OPT_FORCE)) {
                postAuth.add(GlobalPlatformCookbook.set_card_status(GPRegistryEntryNG.ISDLifeCycle.INITIALIZED));
            }
            postAuth.add(GlobalPlatformCookbook.set_card_status(GPRegistryEntryNG.ISDLifeCycle.SECURED));
        }

        if (args.has(OPT_LOCK_APPLET)) {
            postAuth.add(GlobalPlatformCookbook.set_applet_status(args.valueOf(OPT_LOCK_APPLET), true));
        }
        if (args.has(OPT_UNLOCK_APPLET)) {
            postAuth.add(GlobalPlatformCookbook.set_applet_status(args.valueOf(OPT_UNLOCK_APPLET), false));
        }

        if (args.has(OPT_RENAME_ISD)) {
            postAuth.add(GlobalPlatformCookbook.rename_isd(args.valueOf(OPT_RENAME_ISD)));
        }

        // Key replacement (most dangerous - last before listing)
        if (args.has(OPT_LOCK) || args.has(OPT_LOCK_ENC) || args.has(OPT_LOCK_MAC) || args.has(OPT_LOCK_DEK)) {
            PlaintextCardKeys newKeys;
            if (args.has(OPT_LOCK)) {
                var lockKey = parseNGKeySpec(args.valueOf(OPT_LOCK));
                newKeys = (PlaintextCardKeys) lockKey.orElseThrow(() -> new IllegalArgumentException("Invalid lock key"));
            } else if (args.has(OPT_LOCK_ENC) && args.has(OPT_LOCK_MAC) && args.has(OPT_LOCK_DEK)) {
                newKeys = PlaintextCardKeys.fromKeys(args.valueOf(OPT_LOCK_ENC).v(), args.valueOf(OPT_LOCK_MAC).v(), args.valueOf(OPT_LOCK_DEK).v());
            } else {
                throw new IllegalArgumentException("Use either --lock or --lock-enc/mac/dek");
            }
            var kdf = PlaintextCardKeys.KDF_TEMPLATES.getOrDefault(args.valueOf(OPT_LOCK_KDF), args.valueOf(OPT_LOCK_KDF));
            if (kdf != null) {
                newKeys = newKeys.withKdfTemplate(kdf);
            }
            if (args.has(OPT_NEW_KEY_VERSION)) {
                newKeys = newKeys.withVersion(args.valueOf(OPT_NEW_KEY_VERSION));
            }
            if (newKeys.keyInfo().version() == 0) {
                newKeys = newKeys.withVersion(1); // default
            }
            postAuth.add(GlobalPlatformCookbook.put_key_set_diversified(keys, newKeys, true));
        }

        // Informational (query final state)
        if (args.has(OPT_LIST)) {
            postAuth.add(GlobalPlatformCookbook.get_registry().consume(reg -> printRegistry(reg, args.has(OPT_VERBOSE))));
        }

        return new RecipePlan(List.copyOf(preAuth), List.copyOf(postAuth));
    }

    // Build reader selector from CLI options and environment
    static ReaderSelector buildReaderSelector(OptionSet args, Map<String, String> env) {
        var selector = Readers.fromPreferences(Preferences.fromEnvironment(), READER_PREF, READER_IGNORE_PREF);

        if (args.hasArgument(OPT_READER)) {
            selector = selector.select(args.valueOf(OPT_READER));
        }

        if (args.has(OPT_PCSC_EXCLUSIVE) || Boolean.parseBoolean(env.getOrDefault(ENV_GP_PCSC_EXCLUSIVE, "false"))) {
            selector = selector.exclusive();
        }
        selector = selector.transactions(Boolean.parseBoolean(env.getOrDefault(ENV_GP_PCSC_TRANSACT, "true")));
        selector = selector.reset(Boolean.parseBoolean(env.getOrDefault(ENV_GP_PCSC_RESET, "false")));
        if (args.has(OPT_DEBUG)) {
            selector = selector.log(System.out);
        }
        return selector;
    }

    // Execute pre-auth and post-auth recipes against a card
    static int executeRecipes(BIBOSA stack, RecipePlan plan, CardKeys keys, EnumSet<APDUMode> mode, Preferences prefs) {
        var channel = new APDUBIBO(stack);
        var rawChef = Chef.of(channel);
        for (var r : plan.preAuth()) {
            prefs = prefs.merge(rawChef.serve(r, prefs).preferences());
        }
        if (!plan.postAuth().isEmpty()) {
            var dish = rawChef.serve(GlobalPlatformCookbook.open_secure_channel(keys, mode), prefs);
            prefs = prefs.merge(dish.preferences()).with(GlobalPlatformCookbook.SESSION_CONTEXT, dish.value().sessionContext());
            var secBibo = SecureChannelState.secure(new BIBOSA(channel, prefs), dish.value());
            prefs = secBibo.preferences();
            var secChef = Chef.of(secBibo);
            for (var r : plan.postAuth()) {
                prefs = prefs.merge(secChef.serve(r, prefs).preferences());
            }
        }
        return 0;
    }

    // Entry point from GPTool's -ng jump
    public static int execute(String[] argv) {
        var ret = 1;
        try {
            var args = parseArguments(argv);
            setupLogging(args);
            showPreamble(argv, args);

            var cardless = handleCardless(args);
            if (cardless.isPresent()) {
                return cardless.getAsInt();
            }

            var env = System.getenv();

            // List readers if -r without argument
            if (args.has(OPT_READER) && !args.hasArgument(OPT_READER)) {
                var selector = Readers.fromPreferences(Preferences.fromEnvironment(), READER_PREF, READER_IGNORE_PREF);
                System.out.println("Available readers:");
                selector.list().forEach(r -> System.out.printf("- %s%n", r.name()));
                return 0;
            }

            var keys = resolveKeys(args, env);
            var cap = args.has(OPT_CAP) ? CAPFile.fromFile(args.valueOf(OPT_CAP).toPath()) : null;
            var mode = resolveMode(args);
            var cliPrefs = buildCliPrefs(args);
            var plan = buildRecipes(args, env, keys, cap, cliPrefs);

            var selector = buildReaderSelector(args, env);
            ret = selector.open(stack -> executeRecipes(stack, plan, keys, mode, cliPrefs));
        } catch (NoMatchingReaderException e) {
            System.err.println("Specify reader with -r/$GP_READER; available readers:");
            e.getAvailable().forEach(r -> System.err.printf("- %s%n", r));
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid argument: " + e.getMessage());
            trace(e);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            trace(e);
        }
        return ret;
    }

    static boolean onlyHasArg(OptionSet args, OptionSpec<?> s) {
        var needle = args.specs().stream().filter(args::has).count();
        var hay = args.specs().stream().filter(e -> args.has(e) && e != s).count();
        return needle == 1 && hay == 0;
    }

    // Main entry point when called with a BIBOSA stack
    public int run(BIBOSA stack, String[] argv) {
        try {
            var args = parseArguments(argv);
            setupLogging(args);
            var env = System.getenv();
            var keys = resolveKeys(args, env);
            var cap = args.has(OPT_CAP) ? CAPFile.fromFile(args.valueOf(OPT_CAP).toPath()) : null;
            var cliPrefs = buildCliPrefs(args);
            var plan = buildRecipes(args, env, keys, cap, cliPrefs);
            return executeRecipes(stack, plan, keys, resolveMode(args), cliPrefs);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            trace(e);
            return 1;
        }
    }

    // Parse a key specification string into NG CardKeys
    private static Optional<CardKeys> parseNGKeySpec(String spec) {
        if (spec == null || spec.isBlank()) {
            return Optional.empty();
        }
        spec = spec.trim();
        try {
            for (var d : PlaintextCardKeys.KDF_TEMPLATES.entrySet()) {
                if (spec.toLowerCase(Locale.ROOT).startsWith(d.getKey() + ":")) {
                    var k = hexOrDefault(spec.substring(d.getKey().length() + 1));
                    return Optional.of(PlaintextCardKeys.fromMasterKey(k, d.getValue()));
                }
            }
            var k = hexOrDefault(spec);
            return Optional.of(PlaintextCardKeys.fromMasterKey(k));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    // Build domain install params: append SCP version, allow-to, allow-from tags if not already present
    private static byte[] domain_install_params(byte[] baseParams, GPSecureChannelVersion scpVersion,
            boolean allowTo, boolean allowFrom) {
        List<TLV> parsed;
        try {
            parsed = TLV.parse(baseParams);
        } catch (TLVParseException e) {
            return baseParams;
        }
        var p = baseParams;
        if (scpVersion != null && TLV.find(parsed, Tag.ber(0x81)).isEmpty()) {
            p = GPUtils.concatenate(p, TLV.of(Tag.ber(0x81), new byte[]{scpVersion.scp.getValue(), (byte) scpVersion.i}).encode());
        }
        if (allowTo && TLV.find(parsed, Tag.ber(0x82)).isEmpty()) {
            p = GPUtils.concatenate(p, TLV.of(Tag.ber(0x82), new byte[]{0x20, 0x20}).encode());
        }
        if (allowFrom && TLV.find(parsed, Tag.ber(0x87)).isEmpty()) {
            p = GPUtils.concatenate(p, TLV.of(Tag.ber(0x87), new byte[]{0x20, 0x20}).encode());
        }
        return p;
    }

    private static byte[] hexOrDefault(String v) {
        if ("default".startsWith(v.toLowerCase(Locale.ROOT))) {
            return PlaintextCardKeys.defaultKeyBytes();
        }
        return HexUtils.stringToBin(v);
    }

    // NOTE: Integer is used because byte[] is not good for a set.
    @SuppressWarnings("StringSplitter")
    static List<Integer> split(String s) {
        // remove whitespace and "0x" instances
        s = s.replaceAll("\\s+", "").replaceAll("0[xX]", "");

        // If longer than 4 and contains comma - try to parse as list
        if (s.contains(",") && s.length() > 4) {
            var parts = s.split(",");
            var result = new ArrayList<Integer>();

            for (String part : parts) {
                result.add(hex2int(part));
            }
            return List.copyOf(result);
        } else {
            return List.of(hex2int(s));
        }
    }

    static int hex2int(String s) {
        try {
            var value = Integer.parseInt(s, 16);
            if (value < 0x0000 || value > 0xFFFF) {
                throw new IllegalArgumentException("Value out of range (0x0000-0xFFFF): 0x" + Integer.toHexString(value));
            }
            return value;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid hex: " + s);
        }
    }

    // Create a small oracle that knows how to handle padding for different DGI-s
    private static Function<byte[], DGIData.Type> paddingOracle(OptionSet args) {
        var padded = args.valuesOf(OPT_DGI_PADDED).stream().flatMap(s -> GPToolNG.split(s).stream()).collect(Collectors.toSet());
        var unpadded = args.valuesOf(OPT_DGI_UNPADDED).stream().flatMap(s -> GPToolNG.split(s).stream()).collect(Collectors.toSet());

        return s -> {
            var k = ((s[0] & 0xFF) << 8) | (s[1] & 0xFF);
            if (padded.contains(k)) {
                return DGIData.Type.PADDING;
            } else if (unpadded.contains(k)) {
                return DGIData.Type.NOPADDING;
            } else {
                return DGIData.Type.PLAINTEXT;
            }
        };
    }

    private static Set<GPRegistryEntryNG.Privilege> getPrivilegesNG(OptionSet args) {
        var privs = EnumSet.noneOf(GPRegistryEntryNG.Privilege.class);
        if (args.has(OPT_PRIVS)) {
            for (String p : args.valuesOf(OPT_PRIVS)) {
                for (String s : p.split(",", -1)) {
                    privs.add(GPRegistryEntryNG.Privilege.lookup(s.trim()).orElseThrow(() -> new IllegalArgumentException("Unknown privilege: " + s.trim())));
                }
            }
        }
        return privs;
    }

    private static void trace(Exception e) {
        if (isTrace) {
            e.printStackTrace();
        }
    }

    // === Recipe output helpers ===

    private static void printDiscovery(Preferences discovered) {
        discovered.valueOf(GlobalPlatformCookbook.ISD_AID).ifPresent(aid -> System.out.println("ISD: " + HexUtils.bin2hex(aid.getBytes())));
        discovered.valueOf(GlobalPlatformCookbook.GP_VERSION).ifPresent(v -> System.out.println("GP version: " + v));
        discovered.valueOf(GlobalPlatformCookbook.SCP_VERSION).ifPresent(v -> System.out.println("SCP version: " + v));
        discovered.valueOf(GlobalPlatformCookbook.CPLC).ifPresent(cplc -> System.out.println(CPLC.fromBytes(cplc).toPrettyString()));
        discovered.valueOf(GlobalPlatformCookbook.IIN).ifPresent(v -> System.out.println("IIN: " + HexUtils.bin2hex(v)));
        discovered.valueOf(GlobalPlatformCookbook.CIN).ifPresent(v -> System.out.println("CIN: " + HexUtils.bin2hex(v)));
        discovered.valueOf(GlobalPlatformCookbook.KDD).ifPresent(v -> System.out.println("KDD: " + HexUtils.bin2hex(v)));
        discovered.valueOf(GlobalPlatformCookbook.SSC).ifPresent(v -> System.out.println("SSC: " + HexUtils.bin2hex(v)));
        discovered.valueOf(GlobalPlatformCookbook.CARD_DATA).ifPresent(v -> System.out.println("Card Data: " + HexUtils.bin2hex(v)));
        discovered.valueOf(GlobalPlatformCookbook.CARD_CAPABILITIES).ifPresent(v -> System.out.println("Card Capabilities: " + HexUtils.bin2hex(v)));
        discovered.valueOf(GlobalPlatformCookbook.KEY_INFO).ifPresent(v -> System.out.println("Key Info: " + HexUtils.bin2hex(v)));
    }

    private static void printRegistry(GPRegistryNG registry, boolean verbose) {
        var tab = "     ";
        for (var e : registry) {
            System.out.println(e.kind().toShortString() + ": " + HexUtils.bin2hex(e.aid().getBytes()) + " (" + e.getLifeCycleString() + ")");

            if (verbose) {
                e.getDomain().ifPresent(d -> System.out.println(tab + "Parent:   " + d));
                if (e.isPackage()) {
                    System.out.println(tab + "Version:  " + e.getVersionString());
                    for (var m : e.modules()) {
                        System.out.println(tab + "Applet:   " + HexUtils.bin2hex(m.getBytes()));
                    }
                } else {
                    e.getSource().ifPresent(s -> System.out.println(tab + "From:     " + s));
                    if (!e.privileges().isEmpty()) {
                        System.out.println(tab + "Privs:    " + e.privileges().stream().map(Enum::toString).collect(Collectors.joining(", ")));
                    }
                }
            }
            System.out.println();
        }
    }
}
