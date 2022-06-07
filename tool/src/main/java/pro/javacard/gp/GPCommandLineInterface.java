/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2018 Martin Paljak, martin@martinpaljak.net
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
 */
package pro.javacard.gp;

import apdu4j.core.HexBytes;
import joptsimple.*;
import joptsimple.util.EnumConverter;
import pro.javacard.AID;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

abstract class GPCommandLineInterface {
    static OptionParser parser = new OptionParser();
    // Generic options
    protected static OptionSpec<Void> OPT_VERSION = parser.acceptsAll(Arrays.asList("V", "version"), "Show information about the program");
    protected static OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "?", "help"), "Shows this help").forHelp();
    protected static OptionSpec<AID> OPT_CONNECT = parser.acceptsAll(Arrays.asList("c", "connect"), "Connect to app/domain").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<AID> OPT_SDAID = parser.accepts("sdaid", "(deprecated) ISD AID").availableUnless(OPT_CONNECT).withRequiredArg().ofType(AID.class);

    protected static OptionSpec<Void> OPT_DEBUG = parser.acceptsAll(Arrays.asList("d", "debug"), "Show PC/SC and APDU trace");
    protected static OptionSpec<Void> OPT_VERBOSE = parser.acceptsAll(Arrays.asList("v", "verbose"), "Be verbose about operations");
    protected static OptionSpec<String> OPT_READER = parser.acceptsAll(Arrays.asList("r", "reader"), "Use specific reader").withRequiredArg().describedAs("reader");
    protected static OptionSpec<Void> OPT_LIST = parser.acceptsAll(Arrays.asList("l", "list"), "List the contents of the card");
    protected static OptionSpec<Void> OPT_INFO = parser.acceptsAll(Arrays.asList("i", "info"), "Show information");
    protected static OptionSpec<HexBytes> OPT_APDU = parser.acceptsAll(Arrays.asList("a", "apdu"), "Send raw APDU").withRequiredArg().ofType(HexBytes.class).describedAs("APDU");
    protected static OptionSpec<HexBytes> OPT_SECURE_APDU = parser.acceptsAll(Arrays.asList("s", "secure-apdu"), "Send raw APDU via SCP").withRequiredArg().ofType(HexBytes.class).describedAs("APDU");
    protected static OptionSpec<Void> OPT_FORCE = parser.acceptsAll(Arrays.asList("f", "force"), "Force operations");
    protected static OptionSpec<Void> OPT_SAD = parser.acceptsAll(Arrays.asList("F", "no-felix"), "Disable Felix mode DWIM");

    // Applet loading operations
    protected static OptionSpec<File> OPT_CAP = parser.accepts("cap", "Use a CAP file as source").withRequiredArg().ofType(File.class).describedAs("capfile");
    protected static OptionSpec<AID> OPT_CREATE = parser.accepts("create", "Create new instance of an applet").withRequiredArg().ofType(AID.class).describedAs("AID");
    protected static OptionSpec<AID> OPT_APPLET = parser.accepts("applet", "Applet AID").withRequiredArg().ofType(AID.class).describedAs("AID");
    protected static OptionSpec<AID> OPT_PACKAGE = parser.acceptsAll(Arrays.asList("package", "pkg"), "Package AID").withRequiredArg().ofType(AID.class).describedAs("AID");

    protected static OptionSpec<File> OPT_LOAD = parser.accepts("load", "Load a CAP file").withRequiredArg().ofType(File.class).describedAs("capfile");

    protected static OptionSpec<File> OPT_INSTALL = parser.accepts("install", "Install applet(s) from CAP").withRequiredArg().ofType(File.class).describedAs("capfile");
    protected static OptionSpec<HexBytes> OPT_PARAMS = parser.accepts("params", "Installation parameters").withRequiredArg().ofType(HexBytes.class).describedAs("hex");
    protected static OptionSpec<String> OPT_PRIVS = parser.accepts("privs", "Specify privileges for installation").withRequiredArg().describedAs("privs");

    protected static OptionSpec<File> OPT_UNINSTALL = parser.accepts("uninstall", "Uninstall applet/package").withRequiredArg().ofType(File.class).describedAs("capfile");
    protected static OptionSpec<AID> OPT_DELETE = parser.accepts("delete", "Delete applet/package").withRequiredArg().ofType(AID.class);

    protected static OptionSpec<Void> OPT_DEFAULT = parser.accepts("default", "Indicate Default Selected privilege");
    protected static OptionSpec<AID> OPT_DOMAIN = parser.accepts("domain", "Create supplementary security domain").withRequiredArg().ofType(AID.class);

    // Card an applet lifecycle management
    protected static OptionSpec<AID> OPT_LOCK_APPLET = parser.accepts("lock-applet", "Lock applet").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<AID> OPT_UNLOCK_APPLET = parser.accepts("unlock-applet", "Unlock applet").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<Void> OPT_LOCK_CARD = parser.accepts("lock-card", "Lock card");
    protected static OptionSpec<Void> OPT_UNLOCK_CARD = parser.accepts("unlock-card", "Unlock card");
    protected static OptionSpec<Void> OPT_INITIALIZE_CARD = parser.accepts("initialize-card", "Transition ISD to INITIALIZED state");
    protected static OptionSpec<Void> OPT_SECURE_CARD = parser.accepts("secure-card", "Transition ISD to SECURED state");

    // pre-personalization, CPLC
    protected static OptionSpec<HexBytes> OPT_SET_PRE_PERSO = parser.accepts("set-pre-perso", "Set PrePerso data in CPLC").withRequiredArg().ofType(HexBytes.class).describedAs("data");
    protected static OptionSpec<HexBytes> OPT_SET_PERSO = parser.accepts("set-perso", "Set Perso data in CPLC").withRequiredArg().ofType(HexBytes.class).describedAs("data");
    protected static OptionSpec<Void> OPT_TODAY = parser.accepts("today", "Set date to today when updating CPLC");

    // SCP key handling
    protected static OptionSpec<String> OPT_KEY = parser.acceptsAll(Arrays.asList("k", "key"), "Specify key").withRequiredArg().describedAs("key");
    protected static OptionSpec<PlaintextKeys.KDF> OPT_KEY_KDF = parser.accepts("key-kdf", "Use KDF with master key").withRequiredArg().withValuesConvertedBy(new KDFConverter());

    protected static OptionSpec<HexBytes> OPT_KEY_ENC = parser.accepts("key-enc", "Specify card ENC key").withRequiredArg().ofType(HexBytes.class).describedAs("key");
    protected static OptionSpec<HexBytes> OPT_KEY_MAC = parser.accepts("key-mac", "Specify card MAC key").withRequiredArg().ofType(HexBytes.class).describedAs("key");
    protected static OptionSpec<HexBytes> OPT_KEY_DEK = parser.accepts("key-dek", "Specify card DEK key").withRequiredArg().ofType(HexBytes.class).describedAs("key");

    protected static OptionSpec<String> OPT_LOCK = parser.accepts("lock", "Set new key").withRequiredArg().describedAs("key");
    protected static OptionSpec<PlaintextKeys.KDF> OPT_LOCK_KDF = parser.accepts("lock-kdf", "Use KDF with lock key").withRequiredArg().withValuesConvertedBy(new KDFConverter());

    protected static OptionSpec<HexBytes> OPT_LOCK_ENC = parser.accepts("lock-enc", "Set new ENC key").withRequiredArg().ofType(HexBytes.class).describedAs("key");
    protected static OptionSpec<HexBytes> OPT_LOCK_MAC = parser.accepts("lock-mac", "Set new MAC key").withRequiredArg().ofType(HexBytes.class).describedAs("key");
    protected static OptionSpec<HexBytes> OPT_LOCK_DEK = parser.accepts("lock-dek", "Set new DEK key").withRequiredArg().ofType(HexBytes.class).describedAs("key");

    protected static OptionSpec<Void> OPT_UNLOCK = parser.accepts("unlock", "(deprecated) Set default test key");

    // Legacy shorthands
    protected static OptionSpec<Void> OPT_EMV = parser.accepts("emv", "(deprecated) Use EMV KDF");
    protected static OptionSpec<Void> OPT_VISA2 = parser.accepts("visa2", " (deprecated) Use VISA2 KDF");
    protected static OptionSpec<Void> OPT_KDF3 = parser.accepts("kdf3", " (deprecated) Use SCP03 KDF");

    // Key management
    protected static OptionSpec<Integer> OPT_KEY_VERSION = parser.accepts("key-ver", "Specify key version").withRequiredArg().ofType(Integer.class).withValuesConvertedBy(new HexIntegerConverter()).describedAs("version");
    protected static OptionSpec<Key> OPT_PUT_KEY = parser.accepts("put-key", "Put a new key").withRequiredArg().ofType(Key.class).describedAs("PEM or hex");
    protected static OptionSpec<Key> OPT_REPLACE_KEY = parser.accepts("replace-key", "Put a new key, forcing replace").availableUnless(OPT_PUT_KEY).withRequiredArg().ofType(Key.class).describedAs("PEM or hex");
    protected static OptionSpec<Integer> OPT_NEW_KEY_VERSION = parser.accepts("new-keyver", "Key version for the new key").requiredIf(OPT_PUT_KEY, OPT_REPLACE_KEY).withRequiredArg().ofType(Integer.class).withValuesConvertedBy(new HexIntegerConverter()).describedAs("key version");

    protected static OptionSpec<Integer> OPT_DELETE_KEY = parser.accepts("delete-key", "Delete key").withRequiredArg().ofType(Integer.class).withValuesConvertedBy(new HexIntegerConverter()).describedAs("version");

    // Delegated management
    protected static OptionSpec<Key> OPT_DM_KEY = parser.accepts("dm-key", "Delegated Management key").withRequiredArg().ofType(Key.class).describedAs("PEM or hex");
    protected static OptionSpec<HexBytes> OPT_DM_TOKEN = parser.accepts("dm-token", "Delegated Management token").availableUnless(OPT_DM_KEY).withRequiredArg().ofType(HexBytes.class).describedAs("token");

    // SSD-s
    protected static OptionSpec<AID> OPT_MOVE = parser.accepts("move", "Move something").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<AID> OPT_TO = parser.accepts("to", "Destination domain").requiredIf(OPT_MOVE).withRequiredArg().ofType(AID.class);
    protected static OptionSpec<Void> OPT_ALLOW_TO = parser.accepts("allow-to", "Allow moving to created SSD").availableIf(OPT_DOMAIN);
    protected static OptionSpec<Void> OPT_ALLOW_FROM = parser.accepts("allow-from", "Allow moving from created SSD").availableIf(OPT_DOMAIN);

    // DAP
    protected static OptionSpec<AID> OPT_DAP_DOMAIN = parser.accepts("dap-domain", "Domain to use for DAP verification").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<Void> OPT_SHA256 = parser.accepts("sha256", "Use SHA-256 for LFDB hash, not SHA-1");

    // Personalization and store data
    protected static OptionSpec<HexBytes> OPT_STORE_DATA = parser.accepts("store-data", "STORE DATA blob").withRequiredArg().ofType(HexBytes.class).describedAs("data");
    protected static OptionSpec<HexBytes> OPT_STORE_DATA_CHUNK = parser.accepts("store-data-chunk", "Send STORE DATA commands").withRequiredArg().ofType(HexBytes.class).describedAs("data");

    protected static OptionSpec<AID> OPT_MAKE_DEFAULT = parser.accepts("make-default", "Make AID the default").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<AID> OPT_RENAME_ISD = parser.accepts("rename-isd", "Rename ISD").withRequiredArg().ofType(AID.class).describedAs("new AID");

    // MISC options
    protected static OptionSpec<GPSession.APDUMode> OPT_SC_MODE = parser.accepts("mode", "Secure channel to use").withRequiredArg().ofType(GPSession.APDUMode.class).withValuesConvertedBy(new APDUModeConverter());
    protected static OptionSpec<Integer> OPT_BS = parser.accepts("bs", "Maximum APDU payload size").withRequiredArg().ofType(Integer.class).withValuesConvertedBy(new HexIntegerConverter()).describedAs("bytes");
    protected static OptionSpec<String> OPT_PROFILE = parser.acceptsAll(Arrays.asList("P", "profile"), "Use pre-defined profile").withRequiredArg().describedAs("profile");

    // argument converters
    static class KDFConverter extends EnumConverter<PlaintextKeys.KDF> {
        public KDFConverter() {
            super(PlaintextKeys.KDF.class);
        }
    }

    static class APDUModeConverter extends EnumConverter<GPSession.APDUMode> {
        public APDUModeConverter() {
            super(GPSession.APDUMode.class);
        }
    }

    static class HexIntegerConverter implements ValueConverter<Integer> {
        @Override
        public Integer convert(String s) {
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

    protected static <V> Optional<V> optional(OptionSet args, OptionSpec<V> v) {
        return args.has(v) ? Optional.of(args.valueOf(v)) : Optional.empty();
    }

    protected static OptionSet parseArguments(String[] argv) throws IOException {
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
