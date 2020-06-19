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

import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;

abstract class GPCommandLineInterface {
    static OptionParser parser = new OptionParser();
    // Generic options
    protected static OptionSpec<Void> OPT_VERSION = parser.acceptsAll(Arrays.asList("V", "version"), "Show information about the program");
    protected static OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "?", "help"), "Shows this help").forHelp();
    protected static OptionSpec<String> OPT_CONNECT = parser.acceptsAll(Arrays.asList("c", "connect"), "Connect to app/domain").withRequiredArg().describedAs("AID");
    protected static OptionSpec<String> OPT_SDAID = parser.accepts("sdaid", "(deprecated) ISD AID").availableUnless(OPT_CONNECT).withRequiredArg().describedAs("AID");

    protected static OptionSpec<Void> OPT_DEBUG = parser.acceptsAll(Arrays.asList("d", "debug"), "Show PC/SC and APDU trace");
    protected static OptionSpec<Void> OPT_VERBOSE = parser.acceptsAll(Arrays.asList("v", "verbose"), "Be verbose about operations");
    protected static OptionSpec<String> OPT_READER = parser.acceptsAll(Arrays.asList("r", "reader"), "Use specific reader").withRequiredArg();
    protected static OptionSpec<Void> OPT_LIST = parser.acceptsAll(Arrays.asList("l", "list"), "List the contents of the card");
    protected static OptionSpec<Void> OPT_INFO = parser.acceptsAll(Arrays.asList("i", "info"), "Show information");
    protected static OptionSpec<String> OPT_APDU = parser.acceptsAll(Arrays.asList("a", "apdu"), "Send raw APDU (hex)").withRequiredArg().describedAs("APDU");
    protected static OptionSpec<String> OPT_SECURE_APDU = parser.acceptsAll(Arrays.asList("s", "secure-apdu"), "Send raw APDU (hex) via SCP").withRequiredArg().describedAs("APDU");
    protected static OptionSpec<Void> OPT_FORCE = parser.acceptsAll(Arrays.asList("f", "force"), "Force operation");

    // Applet loading operations
    protected static OptionSpec<File> OPT_CAP = parser.accepts("cap", "Use a CAP file as source").withRequiredArg().ofType(File.class);
    protected static OptionSpec<String> OPT_CREATE = parser.accepts("create", "Create new instance of an applet").withRequiredArg().describedAs("AID");
    protected static OptionSpec<String> OPT_APPLET = parser.accepts("applet", "Applet AID").withRequiredArg().describedAs("AID");
    protected static OptionSpec<String> OPT_PACKAGE = parser.acceptsAll(Arrays.asList("package", "pkg"), "Package AID").withRequiredArg().describedAs("AID");

    protected static OptionSpec<File> OPT_LOAD = parser.accepts("load", "Load a CAP file").withRequiredArg().ofType(File.class);

    protected static OptionSpec<File> OPT_INSTALL = parser.accepts("install", "Install applet(s) from CAP").withOptionalArg().ofType(File.class);
    protected static OptionSpec<String> OPT_PARAMS = parser.accepts("params", "Installation parameters").withRequiredArg().describedAs("HEX");
    protected static OptionSpec<String> OPT_PRIVS = parser.accepts("privs", "Specify privileges for installation").withRequiredArg();

    protected static OptionSpec<File> OPT_UNINSTALL = parser.accepts("uninstall", "Uninstall applet/package").withRequiredArg().ofType(File.class);
    protected static OptionSpec<String> OPT_DELETE = parser.accepts("delete", "Delete applet/package").withOptionalArg().describedAs("AID");

    protected static OptionSpec<Void> OPT_DEFAULT = parser.accepts("default", "Indicate Default Selected privilege");
    protected static OptionSpec<String> OPT_DOMAIN = parser.accepts("domain", "Create supplementary security domain").withRequiredArg().describedAs("AID");

    // Card an applet lifecycle management
    protected static OptionSpec<String> OPT_LOCK_APPLET = parser.accepts("lock-applet", "Lock applet").withRequiredArg().describedAs("AID");
    protected static OptionSpec<String> OPT_UNLOCK_APPLET = parser.accepts("unlock-applet", "Unlock applet").withRequiredArg().describedAs("AID");
    protected static OptionSpec<Void> OPT_LOCK_CARD = parser.accepts("lock-card", "Lock card");
    protected static OptionSpec<Void> OPT_UNLOCK_CARD = parser.accepts("unlock-card", "Unlock card");
    protected static OptionSpec<Void> OPT_INITIALIZE_CARD = parser.accepts("initialize-card", "Transition ISD to INITIALIZED state");
    protected static OptionSpec<Void> OPT_SECURE_CARD = parser.accepts("secure-card", "Transition ISD to SECURED state");

    // pre-personalization, CPLC
    protected static OptionSpec<String> OPT_SET_PRE_PERSO = parser.accepts("set-pre-perso", "Set PrePerso data in CPLC").withRequiredArg().describedAs("data");
    protected static OptionSpec<String> OPT_SET_PERSO = parser.accepts("set-perso", "Set Perso data in CPLC").withRequiredArg().describedAs("data");
    protected static OptionSpec<Void> OPT_TODAY = parser.accepts("today", "Set date to today when updating CPLC");

    // SCP key handling
    protected static OptionSpec<String> OPT_KEYS = parser.accepts("keys", "Use key provider").withRequiredArg().describedAs("provider");

    protected static OptionSpec<String> OPT_KEY = parser.accepts("key", "Specify master key").withRequiredArg().describedAs("key");
    protected static OptionSpec<String> OPT_KEY_KCV = parser.accepts("key-kcv", "Specify master key check value").withRequiredArg().describedAs("KCV");
    protected static OptionSpec<String> OPT_KEY_KDF = parser.accepts("key-kdf", "Use KDF with master key").withRequiredArg().describedAs("kdf");

    protected static OptionSpec<String> OPT_KEY_ENC = parser.accepts("key-enc", "Specify card ENC key").withRequiredArg().describedAs("key");
    protected static OptionSpec<String> OPT_KEY_MAC = parser.accepts("key-mac", "Specify card MAC key").withRequiredArg().describedAs("key");
    protected static OptionSpec<String> OPT_KEY_DEK = parser.accepts("key-dek", "Specify card DEK key").withRequiredArg().describedAs("key");

    protected static OptionSpec<String> OPT_LOCK = parser.accepts("lock", "Set new key").withRequiredArg().describedAs("key");
    protected static OptionSpec<String> OPT_LOCK_KCV = parser.accepts("lock-kcv", "Specify lock key check value").withRequiredArg().describedAs("KCV");
    protected static OptionSpec<String> OPT_LOCK_KDF = parser.accepts("lock-kdf", "Use KDF with lock key").withRequiredArg().describedAs("kdf");

    protected static OptionSpec<String> OPT_LOCK_ENC = parser.accepts("lock-enc", "Set new ENC key").withRequiredArg().describedAs("key");
    protected static OptionSpec<String> OPT_LOCK_MAC = parser.accepts("lock-mac", "Set new MAC key").withRequiredArg().describedAs("key");
    protected static OptionSpec<String> OPT_LOCK_DEK = parser.accepts("lock-dek", "Set new DEK key").withRequiredArg().describedAs("key");

    protected static OptionSpec<Void> OPT_UNLOCK = parser.accepts("unlock", "Set default test key for card key");

    // Legacy shorthands
    protected static OptionSpec<Void> OPT_EMV = parser.accepts("emv", "Use EMV KDF");
    protected static OptionSpec<Void> OPT_VISA2 = parser.accepts("visa2", "Use VISA2 KDF");
    protected static OptionSpec<Void> OPT_KDF3 = parser.accepts("kdf3", "Use SCP03 KDF");

    // Key management
    protected static OptionSpec<String> OPT_KEY_ID = parser.accepts("key-id", "Specify key ID").withRequiredArg();
    protected static OptionSpec<String> OPT_KEY_VERSION = parser.accepts("key-ver", "Specify key version").withRequiredArg();
    protected static OptionSpec<String> OPT_PUT_KEY = parser.accepts("put-key", "Put a new key").withRequiredArg().describedAs("PEM file or key");
    protected static OptionSpec<String> OPT_REPLACE_KEY = parser.accepts("replace-key", "Put a new key, forcing replace").withRequiredArg().describedAs("PEM file or key");
    protected static OptionSpec<String> OPT_NEW_KEY_VERSION = parser.accepts("new-keyver", "Key version for the new key").requiredIf(OPT_PUT_KEY, OPT_REPLACE_KEY).withRequiredArg().describedAs("key version");

    protected static OptionSpec<String> OPT_DELETE_KEY = parser.accepts("delete-key", "Delete key with version").withRequiredArg().describedAs("key version");

    // Delegated management
    protected static OptionSpec<String> OPT_DM_KEY = parser.accepts("dm-key", "Delegated Management key").withRequiredArg().describedAs("path or hex");
    protected static OptionSpec<String> OPT_DM_TOKEN = parser.accepts("dm-token", "Delegated Management token").availableUnless(OPT_DM_KEY).withRequiredArg().describedAs("hex");

    // SSD-s
    protected static OptionSpec<String> OPT_MOVE = parser.accepts("move", "Move something").withRequiredArg().describedAs("AID");
    protected static OptionSpec<String> OPT_TO = parser.accepts("to", "Destination security domain").requiredIf(OPT_MOVE).withRequiredArg().describedAs("AID");
    protected static OptionSpec<Void> OPT_ALLOW_TO = parser.accepts("allow-to", "Allow moving to created SSD").availableIf(OPT_DOMAIN);
    protected static OptionSpec<Void> OPT_ALLOW_FROM = parser.accepts("allow-from", "Allow moving from created SSD").availableIf(OPT_DOMAIN);

    // DAP
    protected static OptionSpec<String> OPT_DAP_DOMAIN = parser.accepts("dap-domain", "Domain to use for DAP verification").withRequiredArg().describedAs("AID");
    protected static OptionSpec<Void> OPT_SHA256 = parser.accepts("sha256", "Use SHA-256 for LFDB hash, not SHA-1");

    // Personalization and store data
    protected static OptionSpec<String> OPT_STORE_DATA = parser.accepts("store-data", "STORE DATA blob").withRequiredArg().describedAs("data");
    protected static OptionSpec<String> OPT_STORE_DATA_CHUNK = parser.accepts("store-data-chunk", "Send STORE DATA commands").withRequiredArg().describedAs("data");

    protected static OptionSpec<String> OPT_MAKE_DEFAULT = parser.accepts("make-default", "Make AID the default").withRequiredArg().describedAs("AID");
    protected static OptionSpec<String> OPT_RENAME_ISD = parser.accepts("rename-isd", "Rename ISD").withRequiredArg().describedAs("new AID");

    // MISC options
    protected static OptionSpec<String> OPT_SC_MODE = parser.accepts("mode", "Secure channel to use").withRequiredArg().describedAs("mac/enc/renc/rmac/clr");
    protected static OptionSpec<Integer> OPT_BS = parser.accepts("bs", "Maximum APDU payload size").withRequiredArg().ofType(Integer.class).describedAs("bytes");
    protected static OptionSpec<Void> OPT_OP201 = parser.accepts("op201", "(deprecated) Enable OpenPlatform 2.0.1 mode");


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
            parser.printHelpOn(System.out);
            System.err.println();
            System.err.println("Invalid non-option arguments: " + String.join(" ", args.nonOptionArguments().stream().map(e -> e.toString()).collect(Collectors.toList())));
            System.exit(1);
        }

        if (args.has(OPT_HELP) || args.specs().size() == 0) {
            parser.printHelpOn(System.out);
            System.exit(0);
        }

        return args;
    }
}
