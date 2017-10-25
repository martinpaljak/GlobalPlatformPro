package pro.javacard.gp;

import apdu4j.HexUtils;

import java.io.PrintStream;

// Middle layer between GPTool (CLI) and GlobalPlatform (session)
public class GPCommands {

    public static void listRegistry(GPRegistry reg, PrintStream out, boolean verbose) {
        String tab = "     ";
        for (GPRegistryEntry e : reg) {
            AID aid = e.getAID();
            out.print(e.getType().toShortString() + ": " + HexUtils.bin2hex(aid.getBytes()) + " (" + e.getLifeCycleString() + ")");
            if (e.getType() != GPRegistryEntry.Kind.IssuerSecurityDomain && verbose) {
                out.println(" (" + GPUtils.byteArrayToReadableString(aid.getBytes()) + ")");
            } else {
                out.println();
            }

            if (e.getDomain() != null) {
                out.println(tab + "Parent:  " + e.getDomain());
            }
            if (e.getType() == GPRegistryEntry.Kind.ExecutableLoadFile) {
                GPRegistryEntryPkg pkg = (GPRegistryEntryPkg) e;
                if (pkg.getVersion() != null) {
                    out.println(tab + "Version: " + pkg.getVersionString());
                }
                for (AID a : pkg.getModules()) {
                    out.print(tab + "Applet:  " + HexUtils.bin2hex(a.getBytes()));
                    if (verbose) {
                        out.println(" (" + GPUtils.byteArrayToReadableString(a.getBytes()) + ")");
                    } else {
                        out.println();
                    }
                }
            } else {
                GPRegistryEntryApp app = (GPRegistryEntryApp) e;
                if (app.getLoadFile() != null) {
                    out.println(tab + "From:    " + app.getLoadFile());
                }
                //if (!app.getPrivileges().isEmpty()) {
                out.println(tab + "Privs:   " + app.getPrivileges());
                //}
            }
            out.println();
        }
    }
}
