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

import apdu4j.CommandAPDU;
import apdu4j.HexUtils;
import apdu4j.ResponseAPDU;
import pro.javacard.AID;

import java.io.IOException;
import java.io.PrintStream;

// Middle layer between GPTool (CLI) and GlobalPlatform (session)
public class GPCommands {

    private static void storeDGI(GPSession gp, byte[] payload) throws GPException, IOException {
        // Single DGI. 0x90 should work as well but 0x80 is actually respected by cards.
        CommandAPDU cmd = new CommandAPDU(GPSession.CLA_GP, GPSession.INS_STORE_DATA, 0x80, 0x00, payload);
        ResponseAPDU response = gp.transmit(cmd);
        GPException.check(response, "STORE DATA failed");
    }

    public static void setPrePerso(GPSession gp, byte[] data) throws GPException, IOException {
        if (data == null || data.length != 8)
            throw new IllegalArgumentException("PrePerso data must be 8 bytes");
        byte[] payload = GPUtils.concatenate(new byte[]{(byte) 0x9f, 0x67, (byte) data.length}, data);
        storeDGI(gp, payload);
    }

    public static void setPerso(GPSession gp, byte[] data) throws GPException, IOException {
        if (data == null || data.length != 8)
            throw new IllegalArgumentException("Perso data must be 8 bytes");
        byte[] payload = GPUtils.concatenate(new byte[]{(byte) 0x9f, 0x66, (byte) data.length}, data);
        storeDGI(gp, payload);
    }

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
                if (e.getVersion() != null) {
                    out.println(tab + "Version: " + e.getVersionString());
                }
                for (AID a : e.getModules()) {
                    out.print(tab + "Applet:  " + HexUtils.bin2hex(a.getBytes()));
                    if (verbose) {
                        out.println(" (" + GPUtils.byteArrayToReadableString(a.getBytes()) + ")");
                    } else {
                        out.println();
                    }
                }
            } else {
                if (e.getLoadFile() != null) {
                    out.println(tab + "From:    " + e.getLoadFile());
                }
                //if (!app.getPrivileges().isEmpty()) {
                out.println(tab + "Privs:   " + e.getPrivileges());
                //}
            }
            out.println();
        }
    }
}
