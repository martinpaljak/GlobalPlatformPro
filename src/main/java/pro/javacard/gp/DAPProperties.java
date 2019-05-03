package pro.javacard.gp;

import joptsimple.OptionSet;
import pro.javacard.AID;

import javax.smartcardio.CardException;

import static pro.javacard.gp.GPCommandLineInterface.OPT_DAP_DOMAIN;
import static pro.javacard.gp.GPCommandLineInterface.OPT_TO;

public class DAPProperties {
    private AID targetDomain = null;
    private AID dapDomain = null;
    private boolean required = false;

    public DAPProperties(OptionSet args, GlobalPlatform gp) throws CardException, GPException {
        // Override target and check for DAP
        if (args.has(OPT_TO)) {
            targetDomain = AID.fromString(args.valueOf(OPT_TO));
            if (gp.getRegistry().getDomain(targetDomain) == null) {
                throw new GPException("Specified target domain is invalid: " + targetDomain);
            }
            if (gp.getRegistry().getDomain(targetDomain).getPrivileges().has(GPRegistryEntry.Privilege.DAPVerification))
                required = true;
        }

        // Check if DAP block is required
        for (GPRegistryEntryApp e : gp.getRegistry().allDomains()) {
            if (e.getPrivileges().has(GPRegistryEntry.Privilege.MandatedDAPVerification))
                required = true;
        }

        // Check if DAP is overriden
        if (args.has(OPT_DAP_DOMAIN)) {
            dapDomain = AID.fromString(args.valueOf(OPT_DAP_DOMAIN));
            GPRegistryEntry.Privileges p = gp.getRegistry().getDomain(dapDomain).getPrivileges();
            if (!(p.has(GPRegistryEntry.Privilege.DAPVerification) || p.has(GPRegistryEntry.Privilege.MandatedDAPVerification))) {
                throw new GPException("Specified DAP domain does not have (Mandated)DAPVerification privilege: " + p.toString());
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
