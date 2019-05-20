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

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

abstract class GPCommandLineInterface {
    protected final static String OPT_ALLOW_TO = "allow-to";
    protected final static String OPT_ALLOW_FROM = "allow-from";
    protected final static String OPT_APDU = "apdu";
    protected final static String OPT_APPLET = "applet"; // can always be shortened, so -app is valid
    protected final static String OPT_BS = "bs";
    protected final static String OPT_CAP = "cap";
    protected final static String OPT_CREATE = "create";
    protected final static String OPT_DAP_DOMAIN = "dap-domain";
    protected final static String OPT_DEBUG = "debug";
    protected final static String OPT_DEFAULT = "default";
    protected final static String OPT_DELETE = "delete";
    protected final static String OPT_DELETE_KEY = "delete-key";
    protected final static String OPT_DOMAIN = "domain";
    protected final static String OPT_MOVE = "move";
    protected final static String OPT_DUMP = "dump";
    protected final static String OPT_EMV = "emv";
    protected final static String OPT_FORCE = "force";
    protected final static String OPT_INFO = "info";
    protected final static String OPT_INITIALIZE_CARD = "initialize-card";
    protected final static String OPT_INSTALL = "install";
    protected final static String OPT_KCV = "kcv";
    protected final static String OPT_KDF3 = "kdf3";
    protected final static String OPT_KDF = "kdf";
    protected final static String OPT_KEY = "key";
    protected final static String OPT_KEYS = "keys";
    protected final static String OPT_KEY_ENC = "key-enc";
    protected final static String OPT_KEY_ID = "key-id";
    protected final static String OPT_KEY_DEK = "key-dek";
    protected final static String OPT_KEY_MAC = "key-mac";
    protected final static String OPT_KEY_VERSION = "key-ver";
    protected final static String OPT_LIST = "list";
    protected final static String OPT_LIST_PRIVS = "list-privs";
    protected final static String OPT_LOAD = "load";
    protected final static String OPT_LOCK = "lock";
    protected final static String OPT_LOCK_ENC = "lock-enc";
    protected final static String OPT_LOCK_MAC = "lock-mac";
    protected final static String OPT_LOCK_DEK = "lock-dek";
    protected final static String OPT_LOCK_KDF = "lock-kdf";

    protected final static String OPT_LOCK_APPLET = "lock-applet";
    protected final static String OPT_LOCK_CARD = "lock-card";
    protected final static String OPT_MAKE_DEFAULT = "make-default";
    protected final static String OPT_NEW_KEY_VERSION = "new-keyver";
    protected final static String OPT_OP201 = "op201";
    protected final static String OPT_PACKAGE = "package";
    protected final static String OPT_PARAMS = "params";
    protected final static String OPT_PRIVS = "privs";
    protected final static String OPT_PUT_KEY = "put-key";
    protected final static String OPT_READER = "reader";
    protected final static String OPT_RENAME_ISD = "rename-isd";
    protected final static String OPT_REPLAY = "replay";
    protected final static String OPT_SC_MODE = "mode";
    protected final static String OPT_SDAID = "sdaid";
    protected final static String OPT_SECURE_APDU = "secure-apdu";
    protected final static String OPT_SECURE_CARD = "secure-card";
    protected final static String OPT_SET_PRE_PERSO = "set-pre-perso";
    protected final static String OPT_SET_PERSO = "set-perso";
    protected final static String OPT_SHA256 = "sha256";
    protected final static String OPT_STORE_DATA = "store-data";
    protected final static String OPT_STORE_DATA_CHUNK = "store-data-chunk";
    protected final static String OPT_TERMINALS = "terminals";
    protected final static String OPT_TERMINATE = "terminate";
    protected final static String OPT_TODAY = "today";
    protected final static String OPT_TO = "to";
    protected final static String OPT_UNINSTALL = "uninstall";
    protected final static String OPT_UNLOCK = "unlock";
    protected final static String OPT_UNLOCK_APPLET = "unlock-applet";
    protected final static String OPT_UNLOCK_CARD = "unlock-card";
    protected final static String OPT_VERBOSE = "verbose";
    protected final static String OPT_VERSION = "version";
    protected final static String OPT_VISA2 = "visa2";
    protected final static String OPT_ORACLE = "oracle";
    protected final static String OPT_ACR_LIST = "acr-list";
    protected final static String OPT_ACR_LIST_ARAM = "acr-list-aram";
    protected final static String OPT_ACR_ADD = "acr-add";
    protected final static String OPT_ACR_AID = "acr-aid";
    protected final static String OPT_ACR_DELETE = "acr-delete";
    protected final static String OPT_ACR_RULE = "acr-rule";
    protected final static String OPT_ACR_CERT_HASH = "acr-hash";
    protected final static String OPT_TOKEN_KEY = "token-key";
    // TODO - include token "as is" with -token

    protected static OptionSet parseArguments(String[] argv) throws IOException {
        OptionSet args = null;
        OptionParser parser = new OptionParser();

        // Generic options
        parser.acceptsAll(Arrays.asList("V", OPT_VERSION), "Show information about the program");
        parser.acceptsAll(Arrays.asList("h", "?", "help"), "Shows this help").forHelp();
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
        parser.accepts(OPT_SECURE_CARD, "Transition ISD to SECURED state");
        parser.accepts(OPT_INITIALIZE_CARD, "Transition ISD to INITIALIZED state");
        // SSD and DAP related options
        parser.accepts(OPT_MOVE, "Move something").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_TO, "Destination security domain").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_ALLOW_TO, "Allow moving to created SSD");
        parser.accepts(OPT_ALLOW_FROM, "Allow moving from created SSD");
        parser.accepts(OPT_DAP_DOMAIN, "Domain to use for DAP verification").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_SHA256, "Use SHA-256 for LFDB hash");

        parser.accepts(OPT_SET_PRE_PERSO, "Set PrePerso data in CPLC").withRequiredArg().describedAs("data");
        parser.accepts(OPT_SET_PERSO, "Set Perso data in CPLC").withRequiredArg().describedAs("data");
        parser.accepts(OPT_TODAY, "Set date to today when updating CPLC");

        parser.accepts(OPT_STORE_DATA, "STORE DATA blob").withRequiredArg().describedAs("data");
        parser.accepts(OPT_STORE_DATA_CHUNK, "Send STORE DATA commands").withRequiredArg().describedAs("data");

        parser.accepts(OPT_TOKEN_KEY, "Path to private key used in Delegated Management token generation").withRequiredArg().describedAs("path");

        parser.accepts(OPT_MAKE_DEFAULT, "Make AID the default").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_RENAME_ISD, "Rename ISD").withRequiredArg().describedAs("new AID");

        parser.accepts(OPT_DELETE, "Delete applet/package").withOptionalArg().describedAs("AID");
        parser.accepts(OPT_DELETE_KEY, "Delete key with version").withRequiredArg();

        parser.accepts(OPT_CREATE, "Create new instance of an applet").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_APPLET, "Applet AID").withRequiredArg().describedAs("AID");
        parser.acceptsAll(Arrays.asList(OPT_PACKAGE, "pkg"), "Package AID").withRequiredArg().describedAs("AID");

        // Key options
        parser.accepts(OPT_KEY, "Specify master key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_KDF, "Use KDF with master key").withRequiredArg().describedAs("kdf");

        parser.accepts(OPT_KCV, "Specify master key check value").withRequiredArg().describedAs("KCV");

        parser.accepts(OPT_KEY_MAC, "Specify card MAC key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_KEY_ENC, "Specify card ENC key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_KEY_DEK, "Specify card DEK key").withRequiredArg().describedAs("key");

        parser.accepts(OPT_EMV, "Use EMV KDF");
        parser.accepts(OPT_VISA2, "Use VISA2 KDF");
        parser.accepts(OPT_KDF3, "Use SCP03 KDF KDF");

        parser.accepts(OPT_ORACLE, "Use an oracle for keying information").withOptionalArg().describedAs("URL");

        parser.accepts(OPT_KEY_ID, "Specify key ID").withRequiredArg();
        parser.accepts(OPT_KEY_VERSION, "Specify key version").withRequiredArg();
        parser.accepts(OPT_PUT_KEY, "Put a new key").withRequiredArg().describedAs("PEM file");

        parser.accepts(OPT_LOCK, "Set new key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_LOCK_KDF, "Use KDF with lock key").withRequiredArg().describedAs("kdf");

        parser.accepts(OPT_LOCK_ENC, "Set new ENC key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_LOCK_MAC, "Set new MAC key").withRequiredArg().describedAs("key");
        parser.accepts(OPT_LOCK_DEK, "Set new DEK key").withRequiredArg().describedAs("key");

        parser.accepts(OPT_UNLOCK, "Set default key for card key");
        parser.accepts(OPT_NEW_KEY_VERSION, "Key version for the new key").withRequiredArg();

        // GP SE access rules
        parser.accepts(OPT_ACR_AID, "ARA-C applet AID").withRequiredArg().describedAs("AID");
        parser.accepts(OPT_ACR_LIST, "List access rules");
        parser.accepts(OPT_ACR_LIST_ARAM, "List access rules from ARA-M");
        parser.accepts(OPT_ACR_ADD, "Add an access rule");
        parser.accepts(OPT_ACR_DELETE, "Delete an access rule");
        parser.accepts(OPT_ACR_RULE, "Access control rule (can be 0x00(NEVER),0x01(ALWAYS) or an APDU filter").withRequiredArg();
        parser.accepts(OPT_ACR_CERT_HASH, "Certificate hash").withRequiredArg().describedAs("SHA1");

        // General GP options
        parser.accepts(OPT_SC_MODE, "Secure channel to use (mac/enc/clr)").withRequiredArg().describedAs("mac/enc/clr");
        parser.accepts(OPT_BS, "maximum APDU payload size").withRequiredArg().ofType(Integer.class).describedAs("bytes");
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

        if (args.has("help") || args.specs().size() == 0) {
            parser.printHelpOn(System.out);
            System.exit(0);
        }

        return args;
    }
}
