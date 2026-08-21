// SPDX-FileCopyrightText: 2015 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gptool;

import apdu4j.core.HexBytes;
import joptsimple.*;
import joptsimple.util.EnumConverter;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPCertificate;
import pro.javacard.gp.GPCurve;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.GPUtils;
import pro.javacard.pace.PACE;

import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

abstract class GPCommandLineInterface {
    static OptionParser parser = new OptionParser();
    // Generic options
    protected static OptionSpec<Void> OPT_VERSION = parser.acceptsAll(Arrays.asList("V", "version"), "Show information about the program");
    protected static OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "?", "help"), "Shows this help").forHelp();
    protected static OptionSpec<AID> OPT_CONNECT = parser.acceptsAll(Arrays.asList("c", "connect"), "Connect to app/domain").withRequiredArg()
            .ofType(AID.class);
    protected static OptionSpec<Void> OPT_DEBUG = parser.acceptsAll(Arrays.asList("d", "debug"), "Show PC/SC and APDU trace");
    protected static OptionSpec<Void> OPT_S16 = parser.accepts("s16", "Use SCP03 S16 mode");

    protected static OptionSpec<Void> OPT_VERBOSE = parser.acceptsAll(Arrays.asList("v", "verbose"), "Be verbose about operations");
    protected static OptionSpec<String> OPT_READER = parser.acceptsAll(Arrays.asList("r", "reader"), "Use specific reader").withOptionalArg()
            .describedAs("reader");
    protected static OptionSpec<Void> OPT_LIST = parser.acceptsAll(Arrays.asList("l", "list"), "List the contents of the card");
    protected static OptionSpec<Void> OPT_INFO = parser.acceptsAll(Arrays.asList("i", "info"), "Show information");
    protected static OptionSpec<String> OPT_APDU = parser.acceptsAll(Arrays.asList("a", "apdu"), "Send raw APDU").withRequiredArg().describedAs("APDU");
    protected static OptionSpec<String> OPT_SECURE_APDU = parser.acceptsAll(Arrays.asList("s", "secure-apdu"), "Send APDU via SCP").withRequiredArg()
            .describedAs("APDU");
    protected static OptionSpec<Void> OPT_FORCE = parser.acceptsAll(Arrays.asList("f", "force"), "Force operations");
    protected static OptionSpec<Void> OPT_SAD = parser.acceptsAll(Arrays.asList("F", "no-felix"), "Disable Felix mode DWIM");

    // Applet loading operations
    protected static OptionSpec<File> OPT_LOAD = parser.accepts("load", "Load a CAP file").withRequiredArg().ofType(File.class).describedAs("capfile");

    protected static OptionSpec<File> OPT_CAP = parser.accepts("cap", "Use a CAP file as pkg/app source").availableUnless(OPT_LOAD).withRequiredArg()
            .ofType(File.class).describedAs("capfile");
    protected static OptionSpec<AID> OPT_CREATE = parser.accepts("create", "Create new instance of an applet (deprecated)").withRequiredArg().ofType(AID.class)
            .describedAs("AID");
    protected static OptionSpec<AID> OPT_APPLET = parser.accepts("applet", "Applet AID").withRequiredArg().ofType(AID.class).describedAs("AID");
    protected static OptionSpec<AID> OPT_PACKAGE = parser.acceptsAll(Arrays.asList("package", "pkg"), "Package AID").availableUnless(OPT_CAP).withRequiredArg()
            .ofType(AID.class).describedAs("AID");

    protected static OptionSpec<String> OPT_INSTALL = parser.accepts("install", "Install applet(s)").withRequiredArg().describedAs("capfile/AID");
    protected static OptionSpec<String> OPT_INSTALL_ONLY = parser.accepts("install-only", "Install applet").availableUnless(OPT_INSTALL).withRequiredArg()
            .describedAs("capfile/AID");

    protected static OptionSpec<HexBytes> OPT_PARAMS = parser.accepts("params", "Installation parameters").withRequiredArg().ofType(HexBytes.class)
            .describedAs("hex");
    protected static OptionSpec<String> OPT_PRIVS = parser.acceptsAll(Arrays.asList("privs", "privileges"), "Specify privileges for installation")
            .withRequiredArg().describedAs("privs");

    protected static OptionSpec<File> OPT_UNINSTALL = parser.accepts("uninstall", "Uninstall applet/package").withRequiredArg().ofType(File.class)
            .describedAs("capfile");
    protected static OptionSpec<AID> OPT_DELETE = parser.accepts("delete", "Delete applet/package").withRequiredArg().ofType(AID.class);

    protected static OptionSpec<Void> OPT_DEFAULT = parser.accepts("default", "Indicate Default Selected privilege");
    protected static OptionSpec<Void> OPT_DEFAULT_CONTACT = parser.accepts("default-contact", "Default Selected on contact interface");
    protected static OptionSpec<Void> OPT_DEFAULT_CONTACTLESS = parser.accepts("default-contactless", "Default Selected on contactless interface");

    protected static OptionSpec<AID> OPT_DOMAIN = parser.accepts("domain", "Create supplementary security domain").withRequiredArg().ofType(AID.class);

    // Card an applet lifecycle management
    protected static OptionSpec<AID> OPT_LOCK_APPLET = parser.accepts("lock-applet", "Lock applet").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<AID> OPT_UNLOCK_APPLET = parser.accepts("unlock-applet", "Unlock applet").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<Void> OPT_LOCK_CARD = parser.accepts("lock-card", "Lock card");
    protected static OptionSpec<Void> OPT_UNLOCK_CARD = parser.accepts("unlock-card", "Unlock card");
    protected static OptionSpec<Void> OPT_INITIALIZE_CARD = parser.accepts("initialize-card", "Transition ISD to INITIALIZED state");
    protected static OptionSpec<Void> OPT_SECURE_CARD = parser.accepts("secure-card", "Transition ISD to SECURED state");

    // pre-personalization, CPLC
    protected static OptionSpec<HexBytes> OPT_SET_PRE_PERSO = parser.accepts("set-pre-perso", "Set PrePerso data in CPLC").withRequiredArg()
            .ofType(HexBytes.class).describedAs("data");
    protected static OptionSpec<HexBytes> OPT_SET_PERSO = parser.accepts("set-perso", "Set Perso data in CPLC").withRequiredArg().ofType(HexBytes.class)
            .describedAs("data");
    protected static OptionSpec<Void> OPT_TODAY = parser.accepts("today", "Set date to today when updating CPLC");

    // SCP key handling
    protected static OptionSpec<String> OPT_KEY = parser.acceptsAll(Arrays.asList("k", "key"), "Specify (master) key").withRequiredArg().describedAs("key");
    protected static OptionSpec<String> OPT_KEY_KDF = parser.accepts("key-kdf", "Use KDF/template with master key").withRequiredArg();

    protected static OptionSpec<HexBytes> OPT_KEY_ENC = parser.accepts("key-enc", "Specify card ENC key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");
    protected static OptionSpec<HexBytes> OPT_KEY_MAC = parser.accepts("key-mac", "Specify card MAC key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");
    protected static OptionSpec<HexBytes> OPT_KEY_DEK = parser.accepts("key-dek", "Specify card DEK key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");

    protected static OptionSpec<String> OPT_LOCK = parser.accepts("lock", "Set new SCP key").withRequiredArg().describedAs("key");
    protected static OptionSpec<String> OPT_LOCK_KDF = parser.accepts("lock-kdf", "Use KDF/template with lock key").withRequiredArg();

    protected static OptionSpec<HexBytes> OPT_LOCK_ENC = parser.accepts("lock-enc", "Set new ENC key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");
    protected static OptionSpec<HexBytes> OPT_LOCK_MAC = parser.accepts("lock-mac", "Set new MAC key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");
    protected static OptionSpec<HexBytes> OPT_LOCK_DEK = parser.accepts("lock-dek", "Set new DEK key").withRequiredArg().ofType(HexBytes.class)
            .describedAs("key");

    // Key management
    protected static OptionSpec<Integer> OPT_KEY_VERSION = parser.accepts("key-ver", "Specify key version").withRequiredArg().ofType(Integer.class)
            .withValuesConvertedBy(new HexIntegerConverter()).describedAs("version");
    protected static OptionSpec<Key> OPT_PUT_KEY = parser.accepts("put-key", "Put a new key").withRequiredArg().ofType(Key.class).describedAs("PEM or hex");
    protected static OptionSpec<Key> OPT_REPLACE_KEY = parser.accepts("replace-key", "Put a new key, forcing replace").availableUnless(OPT_PUT_KEY)
            .withRequiredArg().ofType(Key.class).describedAs("PEM or hex");
    protected static OptionSpec<Integer> OPT_NEW_KEY_VERSION = parser.accepts("new-keyver", "Key version for the new key")
            .requiredIf(OPT_PUT_KEY, OPT_REPLACE_KEY).withRequiredArg().ofType(Integer.class).withValuesConvertedBy(new HexIntegerConverter())
            .describedAs("key version");

    protected static OptionSpec<Integer> OPT_DELETE_KEY = parser.accepts("delete-key", "Delete key").withRequiredArg().ofType(Integer.class)
            .withValuesConvertedBy(new HexIntegerConverter()).describedAs("version");

    // Delegated management
    protected static OptionSpec<Key> OPT_DM_KEY = parser.accepts("dm-key", "Delegated Management key").withRequiredArg().ofType(Key.class)
            .describedAs("PEM or hex");
    protected static OptionSpec<HexBytes> OPT_DM_TOKEN = parser.accepts("dm-token", "Delegated Management token").availableUnless(OPT_DM_KEY).withRequiredArg()
            .ofType(HexBytes.class).describedAs("token");
    protected static OptionSpec<HexBytes> OPT_RECEIPT_KEY = parser.accepts("receipt-key", "Receipt verification key (AES)").withRequiredArg()
            .ofType(HexBytes.class).describedAs("key");

    // SSD-s
    protected static OptionSpec<AID> OPT_MOVE = parser.accepts("move", "Move something").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<AID> OPT_TO = parser.accepts("to", "Destination domain").requiredIf(OPT_MOVE).withRequiredArg().ofType(AID.class);
    protected static OptionSpec<Void> OPT_ALLOW_TO = parser.accepts("allow-to", "Allow moving to created SSD").availableIf(OPT_DOMAIN);
    protected static OptionSpec<Void> OPT_ALLOW_FROM = parser.accepts("allow-from", "Allow moving from created SSD").availableIf(OPT_DOMAIN);

    // DAP
    protected static OptionSpec<AID> OPT_DAP_DOMAIN = parser.accepts("dap-domain", "Domain to use for DAP verification").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<Void> OPT_SHA256 = parser.accepts("sha256", "Use SHA-256 for LFDB hash (deprecated; default)");
    protected static OptionSpec<GPData.LFDBH> OPT_HASH = parser.accepts("hash", "Use <hash> for LFDB hash instead of SHA-256").withRequiredArg()
            .ofType(GPData.LFDBH.class).withValuesConvertedBy(new LFDBHConverter()).describedAs("hash");

    protected static OptionSpec<Key> OPT_DAP_KEY = parser.accepts("dap-key", "DAP key").withRequiredArg().ofType(Key.class).describedAs("PEM or hex");
    protected static OptionSpec<HexBytes> OPT_DAP_SIGNATURE = parser.accepts("dap-signature", "DAP signature").availableUnless(OPT_DAP_KEY).withRequiredArg()
            .ofType(HexBytes.class).describedAs("signature");

    // Personalization and store data
    protected static OptionSpec<HexBytes> OPT_STORE_DATA = parser.accepts("store-data", "STORE DATA blob").withRequiredArg().ofType(HexBytes.class)
            .describedAs("data");
    protected static OptionSpec<HexBytes> OPT_STORE_DATA_CHUNK = parser.accepts("store-data-chunk", "Send STORE DATA commands").withRequiredArg()
            .ofType(HexBytes.class).describedAs("data");
    protected static OptionSpec<AID> OPT_PERSONALIZE = parser.accepts("personalize", "Personalize applet via associated SD").withRequiredArg().ofType(AID.class)
            .describedAs("AID");
    protected static OptionSpec<String> OPT_STORE_DATA_RAW = parser.accepts("store-data-raw", "Send raw STORE DATA APDU via secure channel (P2 auto-managed)")
            .withRequiredArg().describedAs("APDU");

    protected static OptionSpec<AID> OPT_MAKE_DEFAULT = parser.accepts("make-default", "Make AID the default").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<AID> OPT_RENAME_ISD = parser.accepts("rename-isd", "Rename ISD").withRequiredArg().ofType(AID.class).describedAs("new AID");

    // EMV personalization
    protected static OptionSpec<File> OPT_STORE_DGI_FILE = parser.accepts("store-dgi-file", "Send DGI-s from file").withRequiredArg().ofType(File.class)
            .describedAs("DGI file");
    protected static OptionSpec<String> OPT_DGI_PADDED = parser.accepts("dgi-padded", "List of padded encrypted DGI-s").availableIf(OPT_STORE_DGI_FILE)
            .withRequiredArg().ofType(String.class);
    protected static OptionSpec<String> OPT_DGI_UNPADDED = parser.accepts("dgi-unpadded", "List of unpadded encrypted DGI-s").availableIf(OPT_STORE_DGI_FILE)
            .withRequiredArg().ofType(String.class);

    // PACE
    protected static OptionSpec<AID> OPT_PACE = parser.accepts("pace", "Run PACE with CAN against AID").withRequiredArg().ofType(AID.class);
    protected static OptionSpec<AID> OPT_PACE_SM = parser.accepts("pace-sm", "Run PACE with CAN and SM against AID").availableUnless(OPT_PACE).withRequiredArg()
            .ofType(AID.class);

    protected static OptionSpec<String> OPT_CAN = parser.accepts("can", "CAN for PACE").withRequiredArg().ofType(String.class).describedAs("can");
    protected static OptionSpec<PACE.PACECurve> OPT_PACE_CURVE = parser.accepts("pace-curve", "Curve to use").requiredIf(OPT_PACE, OPT_PACE_SM)
            .withRequiredArg().ofType(PACE.PACECurve.class).describedAs("curve");

    // GP certificates (tag '7F21'); offline, no card is touched
    protected static OptionSpec<File> OPT_CERT_IN = parser.accepts("cert-in", "Read certificate(s)").withRequiredArg().ofType(File.class)
            .describedAs("file");
    protected static OptionSpec<Void> OPT_CERT_NEW = parser.accepts("cert-new", "Construct a new certificate").availableUnless(OPT_CERT_IN);
    protected static OptionSpec<File> OPT_CERT_DTBS_IN = parser.accepts("cert-dtbs-in", "Read bytes to be signed").availableUnless(OPT_CERT_IN, OPT_CERT_NEW)
            .withRequiredArg().ofType(File.class).describedAs("file");

    protected static OptionSpec<File> OPT_CERT_OUT = parser.accepts("cert-out", "Write certificate to file").withRequiredArg().ofType(File.class)
            .describedAs("file");
    protected static OptionSpec<Void> OPT_CERT_BIN = parser.accepts("cert-bin", "Output binary");
    protected static OptionSpec<Void> OPT_CERT_HEX = parser.accepts("cert-hex", "Output hex").availableUnless(OPT_CERT_BIN);
    protected static OptionSpec<Void> OPT_CERT_BASE64 = parser.accepts("cert-base64", "Output base64").availableUnless(OPT_CERT_BIN, OPT_CERT_HEX);

    protected static OptionSpec<Key> OPT_CERT_SIGN = parser.accepts("cert-sign", "Sign with CA private key").availableUnless(OPT_CERT_DTBS_IN)
            .withRequiredArg().withValuesConvertedBy(new KeyConverter()).describedAs("PEM or curve:key");
    protected static OptionSpec<String> OPT_CERT_SIGNATURE = parser.accepts("cert-signature", "Attach signature (R||S or DER)")
            .availableUnless(OPT_CERT_SIGN).withRequiredArg().describedAs("file or hex");
    protected static OptionSpec<Void> OPT_CERT_DTBS = parser.accepts("cert-dtbs", "Print the bytes to be signed").availableUnless(OPT_CERT_SIGN,
            OPT_CERT_SIGNATURE);
    protected static OptionSpec<String> OPT_CERT_VERIFY = parser.accepts("cert-verify", "Verify with issuer public key").availableIf(OPT_CERT_IN)
            .withRequiredArg().describedAs("PEM/certificate/key");

    protected static OptionSpec<GPCurve> OPT_CERT_CA_CURVE = parser.accepts("cert-ca-curve", "Curve of the CA key").availableUnless(OPT_CERT_SIGN)
            .withRequiredArg().withValuesConvertedBy(new CurveConverter()).describedAs("curve");

    // Certificate fields, tags of Amendment F v1.4 Table 6-1 and Amendment A v1.2 Table 3-6
    protected static OptionSpec<HexBytes> OPT_CERT_SERIAL = parser.accepts("cert-serial", "Certificate Serial Number ('93')").withRequiredArg()
            .withValuesConvertedBy(new LenientHexConverter()).describedAs("hex or text");
    protected static OptionSpec<HexBytes> OPT_CERT_CA = parser.accepts("cert-ca", "CA Identifier ('42')").withRequiredArg()
            .withValuesConvertedBy(new LenientHexConverter()).describedAs("hex or text");
    protected static OptionSpec<HexBytes> OPT_CERT_SUBJECT = parser.accepts("cert-subject", "Subject Identifier ('5F20')").withRequiredArg()
            .withValuesConvertedBy(new LenientHexConverter()).describedAs("hex or text");
    protected static OptionSpec<HexBytes> OPT_CERT_IMAGE_NUMBER = parser.accepts("cert-image-number", "Security Domain Image Number ('45')")
            .withRequiredArg().withValuesConvertedBy(new LenientHexConverter()).describedAs("hex or text");
    protected static OptionSpec<GPCertificate.Usage> OPT_CERT_USAGE = parser.accepts("cert-usage", "Key Usage ('95')").withRequiredArg()
            .withValuesConvertedBy(new UsageConverter());
    protected static OptionSpec<LocalDate> OPT_CERT_EFFECTIVE = parser.accepts("cert-effective", "Effective Date ('5F25')").withRequiredArg()
            .withValuesConvertedBy(new DateConverter()).describedAs("date");
    protected static OptionSpec<LocalDate> OPT_CERT_EXPIRES = parser.accepts("cert-expires", "Expiration Date ('5F24')").withRequiredArg()
            .withValuesConvertedBy(new DateConverter()).describedAs("date");
    protected static OptionSpec<HexBytes> OPT_CERT_DISCRETIONARY = parser.accepts("cert-discretionary", "Discretionary Data ('53')").withRequiredArg()
            .ofType(HexBytes.class).describedAs("hex");
    protected static OptionSpec<HexBytes> OPT_CERT_DISCRETIONARY_TLV = parser.accepts("cert-discretionary-tlv", "Discretionary Data ('73')")
            .availableUnless(OPT_CERT_DISCRETIONARY).withRequiredArg().ofType(HexBytes.class).describedAs("hex");
    protected static OptionSpec<HexBytes> OPT_CERT_AUTHORIZATIONS = parser.accepts("cert-authorizations", "Authorizations ('BF20')").withRequiredArg()
            .ofType(HexBytes.class).describedAs("hex");
    protected static OptionSpec<String> OPT_CERT_PUBKEY = parser.accepts("cert-pubkey", "Subject public key ('7F49')").withRequiredArg()
            .describedAs("PEM or curve:point");

    // MISC options
    protected static OptionSpec<GPSession.APDUMode> OPT_SC_MODE = parser.accepts("mode", "Secure channel to use").withRequiredArg()
            .ofType(GPSession.APDUMode.class).withValuesConvertedBy(new APDUModeConverter());
    protected static OptionSpec<Integer> OPT_BS = parser.accepts("bs", "Maximum APDU payload block size").withRequiredArg().ofType(Integer.class)
            .withValuesConvertedBy(new HexIntegerConverter()).describedAs("bytes");
    protected static OptionSpec<String> OPT_PROFILE = parser.acceptsAll(Arrays.asList("P", "profile"), "Use pre-defined profile").withRequiredArg()
            .describedAs("profile");

    // Next-gen tool
    protected static OptionSpec<Void> OPT_NG = parser.accepts("ng", "Use next-gen tool");

    // PC/SC options
    protected static OptionSpec<Void> OPT_PCSC_EXCLUSIVE = parser.acceptsAll(Arrays.asList("X", "pcsc-exclusive"), "Exclusive PC/SC access to the reader");

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

    static class KeyConverter implements ValueConverter<Key> {
        @Override
        public Key convert(final String s) {
            return Key.valueOf(s);
        }

        @Override
        public Class<? extends Key> valueType() {
            return Key.class;
        }

        @Override
        public String valuePattern() {
            return "Key";
        }
    }

    static class UsageConverter extends EnumConverter<GPCertificate.Usage> {
        public UsageConverter() {
            super(GPCertificate.Usage.class);
        }
    }

    static class CurveConverter implements ValueConverter<GPCurve> {
        @Override
        public GPCurve convert(final String s) {
            final var valid = Arrays.stream(GPCurve.values()).map(Enum::name).collect(Collectors.joining(","));
            return GPCurve.forName(s).orElseThrow(() -> new IllegalArgumentException(s + " is not a supported curve (valid are: " + valid + ")"));
        }

        @Override
        public Class<? extends GPCurve> valueType() {
            return GPCurve.class;
        }

        @Override
        public String valuePattern() {
            return "Curve";
        }
    }

    // ISO dates, plus the YYYYMMDD that the certificate itself carries
    static class DateConverter implements ValueConverter<LocalDate> {
        @Override
        public LocalDate convert(final String s) {
            try {
                return LocalDate.parse(s, s.length() == 8 ? DateTimeFormatter.BASIC_ISO_DATE : DateTimeFormatter.ISO_LOCAL_DATE);
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException(s + " is not a date (use YYYY-MM-DD)");
            }
        }

        @Override
        public Class<? extends LocalDate> valueType() {
            return LocalDate.class;
        }

        @Override
        public String valuePattern() {
            return "Date";
        }
    }

    static class LenientHexConverter implements ValueConverter<HexBytes> {
        @Override
        public HexBytes convert(final String s) {
            return HexBytes.lenient(s);
        }

        @Override
        public Class<? extends HexBytes> valueType() {
            return HexBytes.class;
        }

        @Override
        public String valuePattern() {
            return "Bytes";
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
