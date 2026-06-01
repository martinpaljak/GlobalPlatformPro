// SPDX-FileCopyrightText: 2015 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.core.HexBytes;
import joptsimple.*;
import joptsimple.util.EnumConverter;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.GPUtils;
import pro.javacard.pace.PACE;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

public abstract class GPCommandLineInterface {
    static OptionParser parser = new OptionParser();
    // Generic options
    protected static final OptionSpec<Void> OPT_VERSION = parser.acceptsAll(Arrays.asList("V", "version"), "Show information about the program");
    protected static final OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "?", "help"), "Shows this help").forHelp();
    protected static final OptionSpec<AID> OPT_CONNECT = parser.acceptsAll(Arrays.asList("c", "connect"), "Connect to app/domain").withRequiredArg()
            .ofType(AID.class);
    protected static final OptionSpec<Void> OPT_DEBUG = parser.acceptsAll(Arrays.asList("d", "debug"), "Show PC/SC and APDU trace");
    protected static final OptionSpec<File> OPT_DUMP = parser.accepts("dump", "Dump APDU trace to file").withRequiredArg().ofType(File.class).describedAs("file");
    protected static final OptionSpec<Void> OPT_S16 = parser.accepts("s16", "Use SCP03 S16 mode");

    protected static final OptionSpec<Void> OPT_VERBOSE = parser.acceptsAll(Arrays.asList("v", "verbose"), "Be verbose about operations");
    protected static final OptionSpec<String> OPT_READER = parser.acceptsAll(Arrays.asList("r", "reader"), "Use specific reader").withOptionalArg()
            .describedAs("reader");
    protected static final OptionSpec<Void> OPT_LIST = parser.acceptsAll(Arrays.asList("l", "list"), "List the contents of the card");
    protected static final OptionSpec<Void> OPT_INFO = parser.acceptsAll(Arrays.asList("i", "info"), "Show information");
    protected static final OptionSpec<String> OPT_APDU = parser.acceptsAll(Arrays.asList("a", "apdu"), "Send raw APDU").withRequiredArg().describedAs("APDU");
    protected static final OptionSpec<String> OPT_SECURE_APDU = parser.acceptsAll(Arrays.asList("s", "secure-apdu"), "Send APDU via SCP").withRequiredArg()
            .describedAs("APDU");
    protected static final OptionSpec<Void> OPT_FORCE = parser.acceptsAll(Arrays.asList("f", "force"), "Force operations");
    protected static final OptionSpec<Void> OPT_SAD = parser.acceptsAll(Arrays.asList("F", "no-felix"), "Disable Felix mode DWIM");

    // Applet loading operations
    protected static final OptionSpec<File> OPT_LOAD = parser.accepts("load", "Load a CAP file").withRequiredArg().ofType(File.class).describedAs("capfile");

    protected static final OptionSpec<File> OPT_CAP = parser.accepts("cap", "Use a CAP file as pkg/app source").availableUnless(OPT_LOAD).withRequiredArg()
            .ofType(File.class).describedAs("capfile");
    protected static final OptionSpec<AID> OPT_CREATE = parser.accepts("create", "Create new instance of an applet (deprecated)").withRequiredArg().ofType(AID.class)
            .describedAs("AID");
    protected static final OptionSpec<AID> OPT_APPLET = parser.accepts("applet", "Applet AID").withRequiredArg().ofType(AID.class).describedAs("AID");
    protected static final OptionSpec<AID> OPT_PACKAGE = parser.acceptsAll(Arrays.asList("package", "pkg"), "Package AID").availableUnless(OPT_CAP).withRequiredArg()
            .ofType(AID.class).describedAs("AID");

    protected static final OptionSpec<AID> OPT_UPDATE = parser.accepts("update", "Update registry entry of an instance (INSTALL [for registry update])").withRequiredArg().ofType(AID.class)
            .describedAs("AID");

    protected static final OptionSpec<String> OPT_INSTALL = parser.accepts("install", "Install applet(s)").withRequiredArg().describedAs("capfile/AID");
    protected static final OptionSpec<String> OPT_INSTALL_ONLY = parser.accepts("install-only", "Install applet").availableUnless(OPT_INSTALL).withRequiredArg()
            .describedAs("capfile/AID");

    protected static final OptionSpec<HexBytes> OPT_PARAMS = parser.accepts("params", "Installation parameters").withRequiredArg().ofType(HexBytes.class)
            .describedAs("hex");
    protected static final OptionSpec<String> OPT_PRIVS = parser.acceptsAll(Arrays.asList("privs", "privileges"), "Specify privileges for installation")
            .withRequiredArg().describedAs("privs");

    protected static final OptionSpec<File> OPT_UNINSTALL = parser.accepts("uninstall", "Uninstall applet/package").withRequiredArg().ofType(File.class)
            .describedAs("capfile");
    protected static final OptionSpec<AID> OPT_DELETE = parser.accepts("delete", "Delete applet/package").withRequiredArg().ofType(AID.class);

    protected static final OptionSpec<Void> OPT_DEFAULT = parser.accepts("default", "Indicate Default Selected privilege");
    protected static final OptionSpec<Void> OPT_DEFAULT_CONTACT = parser.accepts("default-contact", "Default Selected on contact interface");
    protected static final OptionSpec<Void> OPT_DEFAULT_CONTACTLESS = parser.accepts("default-contactless", "Default Selected on contactless interface");

    protected static final OptionSpec<AID> OPT_DOMAIN = parser.accepts("domain", "Create supplementary security domain").withRequiredArg().ofType(AID.class);

    // Contactless (Amendment C) install parameters
    protected static final OptionSpec<Void> OPT_CL_ACTIVATED = parser.accepts("cl-activated", "Install contactless-activated");
    protected static final OptionSpec<AID> OPT_CL_NOTIFY = parser.accepts("cl-notify", "Add to CREL notify list").withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<AID> OPT_CL_NOTIFY_REMOVE = parser.accepts("cl-notify-remove", "Remove from CREL notify list").withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<Integer> OPT_CL_FAMILY = parser.accepts("cl-family", "Application family id").withRequiredArg().ofType(Integer.class)
            .withValuesConvertedBy(new HexIntegerConverter());
    protected static final OptionSpec<Void> OPT_CL_DISPLAY_OPTIONAL = parser.accepts("cl-display-optional", "Display not required");
    protected static final OptionSpec<Void> OPT_CL_CONTACT = parser.accepts("cl-contact", "Enable contact interface access");
    protected static final OptionSpec<Void> OPT_CL_CONTACTLESS = parser.accepts("cl-contactless", "Enable contactless interface access");

    // Contactless Registry Service (CRS) commands
    protected static final OptionSpec<AID> OPT_CRS_LIST = parser.accepts("crs-list", "List contactless applications").withOptionalArg().ofType(AID.class);
    protected static final OptionSpec<Void> OPT_CRS_INFO = parser.accepts("crs-info", "Show CRS version and counter");
    protected static final OptionSpec<AID> OPT_CRS_ACTIVATE = parser.accepts("crs-activate", "Activate on contactless").withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<AID> OPT_CRS_DEACTIVATE = parser.accepts("crs-deactivate", "Deactivate on contactless").withRequiredArg().ofType(AID.class);

    // Card an applet lifecycle management
    protected static final OptionSpec<AID> OPT_LOCK_APPLET = parser.accepts("lock-applet", "Lock applet").withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<AID> OPT_UNLOCK_APPLET = parser.accepts("unlock-applet", "Unlock applet").withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<Void> OPT_LOCK_CARD = parser.accepts("lock-card", "Lock card");
    protected static final OptionSpec<Void> OPT_UNLOCK_CARD = parser.accepts("unlock-card", "Unlock card");
    protected static final OptionSpec<Void> OPT_INITIALIZE_CARD = parser.accepts("initialize-card", "Transition ISD to INITIALIZED state");
    protected static final OptionSpec<Void> OPT_SECURE_CARD = parser.accepts("secure-card", "Transition ISD to SECURED state");

    // pre-personalization, CPLC
    protected static final OptionSpec<HexBytes> OPT_SET_PRE_PERSO = parser.accepts("set-pre-perso", "Set PrePerso data in CPLC").withRequiredArg()
            .ofType(HexBytes.class).describedAs("data");
    protected static final OptionSpec<HexBytes> OPT_SET_PERSO = parser.accepts("set-perso", "Set Perso data in CPLC").withRequiredArg().ofType(HexBytes.class)
            .describedAs("data");
    protected static final OptionSpec<Void> OPT_TODAY = parser.accepts("today", "Set date to today when updating CPLC");

    // SCP key handling
    protected static final OptionSpec<String> OPT_KEY = parser.acceptsAll(Arrays.asList("k", "key"), "Specify (master) key").withRequiredArg().describedAs("key");
    protected static final OptionSpec<String> OPT_KEY_KDF = parser.accepts("key-kdf", "Use KDF/template with master key").withRequiredArg();

    protected static final OptionSpec<HexBytes> OPT_KEY_ENC = parser.accepts("key-enc", "Specify card ENC key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");
    protected static final OptionSpec<HexBytes> OPT_KEY_MAC = parser.accepts("key-mac", "Specify card MAC key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");
    protected static final OptionSpec<HexBytes> OPT_KEY_DEK = parser.accepts("key-dek", "Specify card DEK key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");

    protected static final OptionSpec<String> OPT_LOCK = parser.accepts("lock", "Set new SCP key").withRequiredArg().describedAs("key");
    protected static final OptionSpec<String> OPT_LOCK_KDF = parser.accepts("lock-kdf", "Use KDF/template with lock key").withRequiredArg();

    protected static final OptionSpec<HexBytes> OPT_LOCK_ENC = parser.accepts("lock-enc", "Set new ENC key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");
    protected static final OptionSpec<HexBytes> OPT_LOCK_MAC = parser.accepts("lock-mac", "Set new MAC key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");
    protected static final OptionSpec<HexBytes> OPT_LOCK_DEK = parser.accepts("lock-dek", "Set new DEK key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");

    // Key management
    protected static final OptionSpec<Integer> OPT_KEY_VERSION = parser.accepts("key-ver", "Specify key version").withRequiredArg().ofType(Integer.class)
            .withValuesConvertedBy(new HexIntegerConverter()).describedAs("version");
    protected static final OptionSpec<PlaintextKey> OPT_PUT_KEY = parser.accepts("put-key", "Put a new key").withRequiredArg().ofType(PlaintextKey.class).describedAs("PEM or hex");
    protected static final OptionSpec<PlaintextKey> OPT_REPLACE_KEY = parser.accepts("replace-key", "Put a new key, forcing replace").availableUnless(OPT_PUT_KEY)
            .withRequiredArg().ofType(PlaintextKey.class).describedAs("PEM or hex");
    protected static final OptionSpec<Integer> OPT_NEW_KEY_VERSION = parser.accepts("new-keyver", "Key version for the new key")
            .requiredIf(OPT_PUT_KEY, OPT_REPLACE_KEY).withRequiredArg().ofType(Integer.class).withValuesConvertedBy(new HexIntegerConverter())
            .describedAs("key version");

    protected static final OptionSpec<Integer> OPT_DELETE_KEY = parser.accepts("delete-key", "Delete key").withRequiredArg().ofType(Integer.class)
            .withValuesConvertedBy(new HexIntegerConverter()).describedAs("version");

    // Delegated management
    protected static final OptionSpec<PlaintextKey> OPT_DM_KEY = parser.accepts("dm-key", "Delegated Management key").withRequiredArg().ofType(PlaintextKey.class)
            .describedAs("PEM or hex");
    protected static final OptionSpec<HexBytes> OPT_DM_TOKEN = parser.accepts("dm-token", "Delegated Management token").availableUnless(OPT_DM_KEY).withRequiredArg()
            .ofType(HexBytes.class).describedAs("token");
    protected static final OptionSpec<HexBytes> OPT_RECEIPT_KEY = parser.accepts("receipt-key", "Receipt verification key (AES)").withRequiredArg()
            .ofType(HexBytes.class).describedAs("key");

    // SSD-s
    protected static final OptionSpec<AID> OPT_MOVE = parser.accepts("move", "Move something").withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<AID> OPT_TO = parser.accepts("to", "Destination domain").requiredIf(OPT_MOVE).withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<Void> OPT_ALLOW_TO = parser.accepts("allow-to", "Allow moving to created SSD").availableIf(OPT_DOMAIN);
    protected static final OptionSpec<Void> OPT_ALLOW_FROM = parser.accepts("allow-from", "Allow moving from created SSD").availableIf(OPT_DOMAIN);

    // DAP
    protected static final OptionSpec<AID> OPT_DAP_DOMAIN = parser.accepts("dap-domain", "Domain to use for DAP verification").withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<Void> OPT_SHA256 = parser.accepts("sha256", "Use SHA-256 for LFDB hash (deprecated; default)");
    protected static final OptionSpec<GPData.LFDBH> OPT_HASH = parser.accepts("hash", "Use <hash> for LFDB hash instead of SHA-256").withRequiredArg()
            .ofType(GPData.LFDBH.class).withValuesConvertedBy(new LFDBHConverter()).describedAs("hash");

    protected static final OptionSpec<PlaintextKey> OPT_DAP_KEY = parser.accepts("dap-key", "DAP key").withRequiredArg().ofType(PlaintextKey.class).describedAs("PEM or hex");
    protected static final OptionSpec<HexBytes> OPT_DAP_SIGNATURE = parser.accepts("dap-signature", "DAP signature").availableUnless(OPT_DAP_KEY).withRequiredArg()
            .ofType(HexBytes.class).describedAs("signature");

    // Personalization and store data
    protected static final OptionSpec<HexBytes> OPT_STORE_DATA = parser.accepts("store-data", "STORE DATA blob").withRequiredArg().ofType(HexBytes.class)
            .describedAs("data");
    protected static final OptionSpec<HexBytes> OPT_STORE_DATA_CHUNK = parser.accepts("store-data-chunk", "Send STORE DATA commands").withRequiredArg()
            .ofType(HexBytes.class).describedAs("data");
    protected static final OptionSpec<AID> OPT_PERSONALIZE = parser.accepts("personalize", "Personalize applet via associated SD").withRequiredArg().ofType(AID.class)
            .describedAs("AID");
    protected static final OptionSpec<String> OPT_STORE_DATA_RAW = parser.accepts("store-data-raw", "Send raw STORE DATA APDU via secure channel (P2 auto-managed)")
            .withRequiredArg().describedAs("APDU");

    protected static final OptionSpec<AID> OPT_MAKE_DEFAULT = parser.accepts("make-default", "Make AID the default").withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<AID> OPT_RENAME_ISD = parser.accepts("rename-isd", "Rename ISD").withRequiredArg().ofType(AID.class).describedAs("new AID");

    // EMV personalization
    protected static final OptionSpec<File> OPT_STORE_DGI_FILE = parser.accepts("store-dgi-file", "Send DGI-s from file").withRequiredArg().ofType(File.class)
            .describedAs("DGI file");
    protected static final OptionSpec<String> OPT_DGI_PADDED = parser.accepts("dgi-padded", "List of padded encrypted DGI-s").availableIf(OPT_STORE_DGI_FILE)
            .withRequiredArg().ofType(String.class);
    protected static final OptionSpec<String> OPT_DGI_UNPADDED = parser.accepts("dgi-unpadded", "List of unpadded encrypted DGI-s").availableIf(OPT_STORE_DGI_FILE)
            .withRequiredArg().ofType(String.class);

    // PACE
    protected static final OptionSpec<AID> OPT_PACE = parser.accepts("pace", "Run PACE with CAN against AID").withRequiredArg().ofType(AID.class);
    protected static final OptionSpec<AID> OPT_PACE_SM = parser.accepts("pace-sm", "Run PACE with CAN and SM against AID").availableUnless(OPT_PACE).withRequiredArg()
            .ofType(AID.class);

    protected static final OptionSpec<String> OPT_CAN = parser.accepts("can", "CAN for PACE").withRequiredArg().ofType(String.class).describedAs("can");
    protected static final OptionSpec<PACE.PACECurve> OPT_PACE_CURVE = parser.accepts("pace-curve", "Curve to use").requiredIf(OPT_PACE, OPT_PACE_SM)
            .withRequiredArg().ofType(PACE.PACECurve.class).describedAs("curve");

    // Next-gen tool
    protected static final OptionSpec<Void> OPT_NG = parser.accepts("ng", "Use next-gen tool");

    // MISC options
    protected static final OptionSpec<GPSession.APDUMode> OPT_SC_MODE = parser.accepts("mode", "Secure channel to use").withRequiredArg()
            .ofType(GPSession.APDUMode.class).withValuesConvertedBy(new APDUModeConverter());
    protected static final OptionSpec<Integer> OPT_BS = parser.accepts("bs", "Maximum APDU payload block size").withRequiredArg().ofType(Integer.class)
            .withValuesConvertedBy(new HexIntegerConverter()).describedAs("bytes");
    protected static final OptionSpec<String> OPT_PROFILE = parser.acceptsAll(Arrays.asList("P", "profile"), "Use pre-defined profile").withRequiredArg()
            .describedAs("profile");

    // PC/SC options
    protected static final OptionSpec<Void> OPT_PCSC_EXCLUSIVE = parser.acceptsAll(Arrays.asList("X", "pcsc-exclusive"), "Exclusive PC/SC access to the reader");

    static class APDUModeConverter extends EnumConverter<GPSession.APDUMode> {
        public APDUModeConverter() {
            super(GPSession.APDUMode.class);
        }
    }

    static class HexIntegerConverter implements ValueConverter<Integer> {
        @Override
        public Integer convert(final String s) {
            return GPUtils.intValue(s);
        }

        @Override
        public Class<? extends Integer> valueType() {
            return Integer.class;
        }

        @Override
        public String valuePattern() {
            return "Integer";
        }
    }

    static class LFDBHConverter implements ValueConverter<GPData.LFDBH> {
        @Override
        public GPData.LFDBH convert(final String s) {
            final String valid = String.join(",",
                    Arrays.stream(GPData.LFDBH.values()).map(e -> e.name().toLowerCase(Locale.ROOT)).collect(Collectors.toList()));
            return GPData.LFDBH.fromString(s).orElseThrow(() -> new IllegalArgumentException(s + " is not a valid hash (valid are: " + valid + ")"));
        }

        @Override
        public Class<? extends GPData.LFDBH> valueType() {
            return GPData.LFDBH.class;
        }

        @Override
        public String valuePattern() {
            return "Hash";
        }
    }

    protected static <V> Optional<V> optional(OptionSet args, OptionSpec<V> v) {
        return args.has(v) ? Optional.of(args.valueOf(v)) : Optional.empty();
    }

    protected static OptionSet parseArguments(final String[] argv) throws IOException {
        OptionSet args = null;

        // Parse arguments
        try {
            args = parser.parse(argv);
        } catch (OptionException e) {
            parser.printHelpOn(System.err);
            System.err.println();
            if (e.getCause() != null) {
                System.err.println(e.getMessage() + ": " + e.getCause().getMessage());
            } else {
                System.err.println(e.getMessage());
            }
            System.exit(1);
        }

        if (args.nonOptionArguments().size() > 0) {
            System.err.println();
            System.err.println("Invalid non-option arguments: " + args.nonOptionArguments().stream().map(e -> e.toString()).collect(Collectors.joining(" ")));
            System.err.println("Try gp --help");
            System.exit(1);
        }

        if (args.has(OPT_HELP) || args.specs().size() == 0) {
            parser.printHelpOn(System.out);
            System.exit(0);
        }

        return args;
    }

}
