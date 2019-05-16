package pro.javacard.gp;

import joptsimple.OptionSet;
import pro.javacard.AID;
import pro.javacard.gp.GPRegistryEntry.Privilege;

import java.io.IOException;

import static pro.javacard.gp.GPCommandLineInterface.OPT_DAP_DOMAIN;
import static pro.javacard.gp.GPCommandLineInterface.OPT_TO;

public class DAPProperties {
    private AID targetDomain = null;
    private AID dapDomain = null;
    private boolean required = false;

    public DAPProperties(OptionSet args, GPSession gp) throws IOException, IllegalArgumentException {
        GPRegistry reg = gp.getRegistry();
        // Override target and check for DAP
        if (args.has(OPT_TO)) {
            targetDomain = AID.fromString(args.valueOf(OPT_TO));
            GPRegistryEntry target = reg.getDomain(targetDomain).orElseThrow(() -> new IllegalArgumentException("Target domain does not exist: " + targetDomain));

            required = required || target.hasPrivilege(Privilege.DAPVerification);
        }

        // Check if DAP block is required
        required = required || reg.allDomains().stream().anyMatch( e->e.hasPrivilege(Privilege.MandatedDAPVerification));

        // Check if DAP is overriden
        if (args.has(OPT_DAP_DOMAIN)) {
            dapDomain = AID.fromString(args.valueOf(OPT_DAP_DOMAIN));
            GPRegistryEntry target = reg.getDomain(targetDomain).orElseThrow(() -> new IllegalArgumentException("DAP domain does not exist: " + targetDomain));

            if (!(target.hasPrivilege(Privilege.DAPVerification) || target.hasPrivilege(Privilege.MandatedDAPVerification))) {
                throw new GPException("Specified DAP domain does not have (Mandated)DAPVerification privilege: " + targetDomain.toString());
            }
        }
    }

    public AID getTargetDomain() {
        return targetDomain;
    }

    public AID getDapDomain() {
        return dapDomain;
    }

    public boolean isRequired() {
        return required;
    }
}
