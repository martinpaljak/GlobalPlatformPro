package pro.javacard.capfile.tool;

import org.bouncycastle.util.encoders.Hex;
import pro.javacard.capfile.CAPFile;
import pro.javacard.capfile.CAPFileSigner;
import pro.javacard.sdk.JavaCardSDK;
import pro.javacard.sdk.OffCardVerifier;
import pro.javacard.sdk.VerifierError;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Vector;
import java.util.stream.Collectors;

public class CAPFileTool {

    private final static ArrayList<String> help = new ArrayList<>();
    static {
        help.add("    dump:   capfile <capfile>");
        help.add("    verify: capfile -v <sdkpath> [<targetsdkpath>] <capfile> [<expfiles...>]");
        help.add("    sign:   capfile -s <keyfile> <capfile>");
        help.add("    lfdbh:  capfile -sha256 <capfile>");
    }
    private static boolean has(Vector<String> args, String v) {
        for (String s : args) {
            if (s.equalsIgnoreCase(v)) {
                args.remove(s);
                return true;
            }
        }
        return false;
    }

    public static void main(String[] argv) {
        Vector<String> args = new Vector<>(Arrays.asList(argv));

        if (args.size() < 1 || has(args, "-h")) {
            System.err.println("Usage:");
            help.stream().forEach(s -> System.err.println(s));
            System.exit(1);
        }

        try {
            if (has(args, "-s")) {
                if (args.size() < 2)
                    fail("Usage:\n" + help.get(2));
                String keyfile = args.remove(0);
                Path capfile = Paths.get(args.remove(0));
                CAPFile cap = CAPFile.fromBytes(Files.readAllBytes(capfile));
                cap.dump(System.out);
                try {
                    PrivateKey signingKey = CAPFileSigner.pem2privatekey(keyfile);
                    CAPFileSigner.addSignature(cap, signingKey);
                    Path where = capfile.getParent();
                    if (where == null)
                        where = Paths.get(".");
                    Path tmpfile = Files.createTempFile(where, "capfile", "unsigned");
                    cap.store(Files.newOutputStream(tmpfile));
                    Files.move(tmpfile, capfile, StandardCopyOption.ATOMIC_MOVE);
                    System.out.println("Signed " + capfile);
                } catch (GeneralSecurityException e) {
                    fail("Failed to sign: " + e.getMessage());
                }

            } else if (has(args, "-v")) {
                if (args.size() < 2)
                    fail("Usage:\n" + help.get(1));
                final String sdkpath = args.remove(0);
                final String targetsdkpath;
                final String capfile;
                final String next = args.remove(0);
                if (Files.isDirectory(Paths.get(next))) {
                    targetsdkpath = next;
                    capfile = args.remove(0);
                } else {
                    capfile = next;
                    targetsdkpath = sdkpath;
                }
                Vector<File> exps = new Vector<>(args.stream().map(i -> new File(i)).collect(Collectors.toList()));
                CAPFile cap = CAPFile.fromBytes(Files.readAllBytes(Paths.get(capfile)));
                cap.dump(System.out);
                try {
                    JavaCardSDK sdk = JavaCardSDK.detectSDK(Paths.get(sdkpath)).get();
                    JavaCardSDK target = JavaCardSDK.detectSDK(Paths.get(targetsdkpath)).get();

                    OffCardVerifier verifier = OffCardVerifier.withSDK(sdk);
                    verifier.verifyAgainst(new File(capfile), target, exps);
                    System.out.println("Verified " + capfile);
                } catch (VerifierError e) {
                    fail("Verification failed: " + e.getMessage());
                }
            } else if (has(args, "-sha256")) {
                if (args.size() < 1)
                    fail("Usage:\n" + help.get(3));
                String capfile = args.remove(0);
                CAPFile cap = CAPFile.fromBytes(Files.readAllBytes(Paths.get(capfile)));
                System.out.println(Hex.toHexString(cap.getLoadFileDataHash("SHA-256")));
            } else {
                String capfile = args.remove(0);
                CAPFile cap = CAPFile.fromBytes(Files.readAllBytes(Paths.get(capfile)));
                cap.dump(System.out);
            }
        } catch (IOException | IllegalArgumentException e) {
            fail(e.getMessage());
        }
    }

    private static void fail(String message) {
        System.err.println(message);
        System.exit(1);
    }
}
