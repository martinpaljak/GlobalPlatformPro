/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2017 Martin Paljak, martin@martinpaljak.net
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

import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.capfile.WellKnownAID;
import pro.javacard.gp.GPData.LFDBH;
import pro.javacard.gp.GPRegistryEntry.Privilege;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// Middle layer between GPTool (CLI) and GlobalPlatform (session)
public final class GPCommands {

    private GPCommands() {}

    private static void storeDGI(final GPSession gp, final byte[] payload) throws GPException, IOException {
        // Single DGI. 0x90 should work as well but 0x80 is actually respected by cards.
        final var cmd = new CommandAPDU(GPSession.CLA_GP, GPSession.INS_STORE_DATA, 0x80, 0x00, payload);
        final var response = gp.transmit(cmd);
        GPException.check(response, "STORE DATA failed");
    }

    public static void setPrePerso(final GPSession gp, final byte[] data) throws GPException, IOException {
        if (data == null || data.length != 8) {
            throw new IllegalArgumentException("PrePerso data must be 8 bytes");
        }
        final byte[] payload = GPUtils.concatenate(new byte[] { (byte) 0x9f, 0x67, (byte) data.length }, data);
        storeDGI(gp, payload);
    }

    public static void setPerso(final GPSession gp, final byte[] data) throws GPException, IOException {
        if (data == null || data.length != 8) {
            throw new IllegalArgumentException("Perso data must be 8 bytes");
        }
        final byte[] payload = GPUtils.concatenate(new byte[] { (byte) 0x9f, 0x66, (byte) data.length }, data);
        storeDGI(gp, payload);
    }

    public static void listRegistry(final GPRegistry reg, final PrintStream out, final boolean verbose) {
        final var tab = "     ";
        for (GPRegistryEntry e : reg) {
            final var aid = e.getAID();
            out.print(e.getType() + ": " + HexUtils.bin2hex(aid.getBytes()) + " (" + e.getLifeCycleString() + ")");
            if (e.getType() != GPRegistryEntry.Kind.ISD && verbose) {
                out.println(" (" + WellKnownAID.getName(aid).orElse(GPUtils.bin2readable(aid.getBytes())) + ")");
            } else {
                out.println();
            }

            if (e.getDomain().isPresent()) {
                out.println(tab + "Parent:   " + e.getDomain().get());
            }
            if (e.getType() == GPRegistryEntry.Kind.PKG) {
                if (e.getVersion() != null) {
                    out.println(tab + "Version:  " + e.getVersionString());
                }
                for (AID a : e.getModules()) {
                    out.print(tab + "Applet:   " + HexUtils.bin2hex(a.getBytes()));
                    if (verbose) {
                        out.println(" (" + WellKnownAID.getName(a).orElse(GPUtils.bin2readable(a.getBytes())) + ")");
                    } else {
                        out.println();
                    }
                }
            } else {
                if (e.getSource().isPresent()) {
                    out.println(tab + "From:     " + e.getSource().get());
                }
                final var implicit = getImplicitString(e);
                implicit.ifPresent(s -> out.println(tab + "Selected: " + s));
                if (!e.getPrivileges().isEmpty()) {
                    out.println(tab + "Privs:    " + e.getPrivileges().stream().map(Enum::toString).collect(Collectors.joining(", ")));
                }
            }
            out.println();
        }
    }

    static Optional<String> getImplicitString(final GPRegistryEntry entry) {
        final Optional<String> contactless = entry.getImplicitlySelectedContactless().isEmpty() ? Optional.empty() : Optional
                .of("Contactless(%s)".formatted(entry.getImplicitlySelectedContactless().stream().map(Object::toString).collect(Collectors.joining(","))));
        final Optional<String> contact = entry.getImplicitlySelectedContact().isEmpty() ? Optional.empty()
                : Optional.of("Contact(%s)".formatted(entry.getImplicitlySelectedContact().stream().map(Object::toString).collect(Collectors.joining(","))));
        return Stream.of(contactless, contact).filter(Optional::isPresent).map(Optional::get).reduce((a, b) -> a + ", " + b);
    }

    // Figure out load parameters
    @SuppressWarnings("StatementSwitchToExpressionSwitch")
    public static void load(final GPSession gp, final CAPFile cap, final AID to, final AID dapAID, final LFDBH hash) throws GPException, IOException {
        final var reg = gp.getRegistry();

        // Override target domain
        final var targetAID = Optional.ofNullable(to).orElse(gp.getAID());

        final var targetDomain = reg.getDomain(targetAID).orElseThrow(() -> new IllegalArgumentException("Target domain does not exist: " + targetAID));

        // Check for DAP with the target domain or Mandatory DAP
        final var dapRequired = targetDomain.hasPrivilege(Privilege.DAPVerification)
                || reg.allDomains().stream().anyMatch(e -> e.hasPrivilege(Privilege.MandatedDAPVerification));

        // Check if DAP domain is overridden
        if (dapAID != null) {
            final var dapTarget = reg.getDomain(targetAID).orElseThrow(() -> new IllegalArgumentException("DAP domain does not exist: " + dapAID));
            if (!(dapTarget.hasPrivilege(Privilege.DAPVerification) || dapTarget.hasPrivilege(Privilege.MandatedDAPVerification))) {
                throw new IllegalArgumentException("Specified DAP domain does not have (Mandated)DAPVerification privilege: " + dapAID);
            }
        }

        final LFDBH lfdbh;
        // Check if hash needs to be included
        if (targetDomain.hasPrivilege(Privilege.DelegatedManagement) || dapRequired || hash != null) {
            lfdbh = Optional.ofNullable(hash).orElse(LFDBH.SHA1);
        } else {
            lfdbh = null;
        }

        // FIXME: see #304
        if (dapRequired) {
            throw new IllegalArgumentException("Broken code, see #304");
        }
        final byte[] dap = null;
        gp.loadCapFile(cap, targetAID, Optional.ofNullable(dapAID).orElse(targetAID), dap, lfdbh);
    }
}
