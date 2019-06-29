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

import apdu4j.HexUtils;
import pro.javacard.AID;

import java.util.*;
import java.util.stream.Collectors;

public class GPRegistryEntry {

    AID aid;
    int lifecycle;
    Kind kind;
    AID domain; // Associated security domain

    // Apps and Domains
    private Privileges privileges = new Privileges();
    private AID loadfile; // source

    // Packages
    private byte[] version;
    private List<AID> modules = new ArrayList<>();


    public Privileges getPrivileges() {
        return privileges;
    }

    void setPrivileges(Privileges privs) {
        privileges = privs;
    }

    public AID getLoadFile() {
        return loadfile;
    }

    public void setLoadFile(AID aid) {
        this.loadfile = aid;
    }


    public boolean hasPrivilege(Privilege p) {
        return privileges.has(p);
    }

    public byte[] getVersion() {
        if (version == null)
            return null;
        return version.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof GPRegistryEntry) {
            GPRegistryEntry o = (GPRegistryEntry) other;
            return o.kind.equals(this.kind) && o.aid.equals(this.aid);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(aid, kind);
    }

    void setVersion(byte[] v) {
        version = v.clone();
    }

    public String getVersionString() {
        if (version == null) {
            return "<null>";
        }
        if (version.length == 2) {
            return version[0] + "." + version[1];
        }
        return "<unknown format " + HexUtils.bin2hex(version) + ">";
    }

    public void addModule(AID aid) {
        modules.add(aid);
    }

    public List<AID> getModules() {
        List<AID> r = new ArrayList<>();
        r.addAll(modules);
        return r;
    }


    static String getLifeCycleString(Kind kind, int lifeCycleState) {
        switch (kind) {
            case IssuerSecurityDomain:
                switch (lifeCycleState) {
                    case 0x01:
                        return "OP_READY";
                    case 0x07:
                        return "INITIALIZED";
                    case 0x0F:
                        return "SECURED";
                    case 0x7F:
                        return "CARD_LOCKED";
                    case 0xFF:
                        return "TERMINATED";
                    default:
                        return "ERROR (0x" + Integer.toHexString(lifeCycleState) + ")";
                }
            case Application:
                if (lifeCycleState == 0x3) {
                    return "INSTALLED";
                } else if (lifeCycleState <= 0x7F) {
                    if ((lifeCycleState & 0x78) != 0x00) {
                        return "SELECTABLE (0x" + Integer.toHexString(lifeCycleState) + ")";
                    } else {
                        return "SELECTABLE";
                    }
                } else if (lifeCycleState > 0x83) {
                    return "LOCKED";
                } else {
                    return "ERROR (0x" + Integer.toHexString(lifeCycleState) + ")";
                }
            case ExecutableLoadFile:
                // GP 2.2.1 Table 11-3
                if (lifeCycleState == 0x1) {
                    return "LOADED";
                } else if (lifeCycleState == 0x00) {
                    // OP201 TODO: remove in v0.5
                    return "LOGICALLY_DELETED";
                } else {
                    return "ERROR (0x" + Integer.toHexString(lifeCycleState) + ")";
                }
            case SecurityDomain:
                // GP 2.2.1 Table 11-5
                if (lifeCycleState == 0x3) {
                    return "INSTALLED";
                } else if (lifeCycleState == 0x7) {
                    return "SELECTABLE";
                } else if (lifeCycleState == 0xF) {
                    return "PERSONALIZED";
                } else if ((lifeCycleState & 0x83) == 0x83) {
                    return "LOCKED";
                } else {
                    return "ERROR (0x" + Integer.toHexString(lifeCycleState) + ")";
                }
            default:
                return "ERROR";
        }
    }

    public AID getAID() {
        return aid;
    }

    void setAID(AID aid) {
        this.aid = aid;
    }

    public AID getDomain() {
        return domain;
    }

    public int getLifeCycle() {
        return lifecycle;
    }

    void setLifeCycle(int lifecycle) {
        this.lifecycle = lifecycle;
    }

    public Kind getType() {
        return kind;
    }

    void setType(Kind type) {
        this.kind = type;
    }

    public boolean isPackage() {
        return kind == Kind.ExecutableLoadFile;
    }

    public boolean isApplet() {
        return kind == Kind.Application;
    }

    public boolean isDomain() {
        return kind == Kind.SecurityDomain || kind == Kind.IssuerSecurityDomain;
    }

    void setDomain(AID dom) {
        this.domain = dom;
    }

    public String toString() {
        return String.format("%s: %s, %s", kind.toShortString(), HexUtils.bin2hex(aid.getBytes()), lifecycle);
    }

    public String getLifeCycleString() {
        return getLifeCycleString(kind, lifecycle);
    }

    public enum Kind {
        IssuerSecurityDomain, Application, SecurityDomain, ExecutableLoadFile;


        public String toShortString() {
            switch (this) {
                case IssuerSecurityDomain:
                    return "ISD";
                case Application:
                    return "APP";
                case SecurityDomain:
                    return "DOM";
                case ExecutableLoadFile:
                    return "PKG";
                default:
                    throw new IllegalStateException("Unknown entry type");
            }
        }
    }

    public enum Privilege {
        SecurityDomain,
        DAPVerification,
        DelegatedManagement,
        CardLock,
        CardTerminate,
        CardReset,
        CVMManagement,
        MandatedDAPVerification,
        TrustedPath,
        AuthorizedManagement,
        TokenVerification,
        GlobalDelete,
        GlobalLock,
        GlobalRegistry,
        FinalApplication,
        GlobalService,
        ReceiptGeneration,
        CipheredLoadFileDataBlock,
        ContactlessActivation,
        ContactlessSelfActivation;

        public static Privilege lookup(String v) {
            for (Privilege d : Privilege.values()) {
                if (d.name().equalsIgnoreCase(v)) {
                    return d;
                }
            }
            return null;
        }
    }

    public static class Privileges {
        private EnumSet<Privilege> privs = EnumSet.noneOf(Privilege.class);

        public static Privileges set(Privilege... privs) {
            Privileges p = new Privileges();
            Arrays.stream(privs).forEach(v -> p.add(v));
            return p;
        }

        // TODO: implement GP 2.2 table 6.2
        // TODO: bitmasks as symbolics, KAT tests
        // See GP 2.2.1 Tables 11-7, 11-8, 11-9
        // See GP 2.1.1 Table 9-7 (matches 2.2 Table 11-7)
        public static Privileges fromBytes(byte[] data) throws GPDataException {
            if (data.length != 1 && data.length != 3) {
                throw new IllegalArgumentException("Privileges must be encoded on 1 or 3 bytes: " + HexUtils.bin2hex(data));
            }
            Privileges p = new Privileges();
            // Process first byte
            int b1 = data[0] & 0xFF;
            if ((b1 & 0x80) == 0x80) {
                p.privs.add(Privilege.SecurityDomain);
            }
            if ((b1 & 0xC1) == 0xC0) {
                p.privs.add(Privilege.DAPVerification);
            }
            if ((b1 & 0xA0) == 0xA0) {
                p.privs.add(Privilege.DelegatedManagement);
            }
            if ((b1 & 0x10) == 0x10) {
                p.privs.add(Privilege.CardLock);
            }
            if ((b1 & 0x8) == 0x8) {
                p.privs.add(Privilege.CardTerminate);
            }
            if ((b1 & 0x4) == 0x4) {
                p.privs.add(Privilege.CardReset);
            }
            if ((b1 & 0x2) == 0x2) {
                p.privs.add(Privilege.CVMManagement);
            }
            if ((b1 & 0xC1) == 0xC1) {
                p.privs.add(Privilege.MandatedDAPVerification);
            }
            if (data.length > 1) {
                int b2 = data[1] & 0xFF;
                if ((b2 & 0x80) == 0x80) {
                    p.privs.add(Privilege.TrustedPath);
                }
                if ((b2 & 0x40) == 0x40) {
                    p.privs.add(Privilege.AuthorizedManagement);
                }
                if ((b2 & 0x20) == 0x20) {
                    p.privs.add(Privilege.TokenVerification); // XXX: mismatch in spec
                }
                if ((b2 & 0x10) == 0x10) {
                    p.privs.add(Privilege.GlobalDelete);
                }
                if ((b2 & 0x8) == 0x8) {
                    p.privs.add(Privilege.GlobalLock);
                }
                if ((b2 & 0x4) == 0x4) {
                    p.privs.add(Privilege.GlobalRegistry);
                }
                if ((b2 & 0x2) == 0x2) {
                    p.privs.add(Privilege.FinalApplication);
                }
                if ((b2 & 0x1) == 0x1) {
                    p.privs.add(Privilege.GlobalService);
                }
                int b3 = data[2] & 0xFF;
                if ((b3 & 0x80) == 0x80) {
                    p.privs.add(Privilege.ReceiptGeneration);
                }
                if ((b3 & 0x40) == 0x40) {
                    p.privs.add(Privilege.CipheredLoadFileDataBlock);
                }
                if ((b3 & 0x20) == 0x20) {
                    p.privs.add(Privilege.ContactlessActivation);
                }
                if ((b3 & 0x10) == 0x10) {
                    p.privs.add(Privilege.ContactlessSelfActivation);
                }
                if ((b3 & 0xF) != 0x0) {
                    // RFU
                    throw new GPDataException("RFU bits set in privileges!");
                }
            }
            return p;
        }

        public static Privileges fromByte(byte b) throws GPDataException {
            return fromBytes(new byte[]{b});
        }

        public byte[] toBytes() {
            EnumSet<Privilege> p = EnumSet.copyOf(privs);
            int b1 = 0x00;
            if (p.remove(Privilege.SecurityDomain)) {
                b1 |= 0x80;
            }
            if (p.remove(Privilege.DAPVerification)) {
                b1 |= 0xC0;
            }
            if (p.remove(Privilege.DelegatedManagement)) {
                b1 |= 0xA0;
            }
            if (p.remove(Privilege.CardLock)) {
                b1 |= 0x10;
            }
            if (p.remove(Privilege.CardTerminate)) {
                b1 |= 0x8;
            }
            if (p.remove(Privilege.CardReset)) {
                b1 |= 0x4;
            }
            if (p.remove(Privilege.CVMManagement)) {
                b1 |= 0x2;
            }
            if (p.remove(Privilege.MandatedDAPVerification)) {
                b1 |= 0xC1;
            }

            // Fits in one byte
            if (p.isEmpty()) {
                return new byte[]{(byte) (b1 & 0xFF)};
            }

            // Second
            int b2 = 0x00;
            if (p.remove(Privilege.TrustedPath)) {
                b2 |= 0x80;
            }
            if (p.remove(Privilege.AuthorizedManagement)) {
                b2 |= 0x40;
            }
            if (p.remove(Privilege.TokenVerification)) {
                b2 |= 0x20;
            }
            if (p.remove(Privilege.GlobalDelete)) {
                b2 |= 0x10;
            }
            if (p.remove(Privilege.GlobalLock)) {
                b2 |= 0x8;
            }
            if (p.remove(Privilege.GlobalRegistry)) {
                b2 |= 0x4;
            }
            if (p.remove(Privilege.FinalApplication)) {
                b2 |= 0x2;
            }
            if (p.remove(Privilege.GlobalService)) {
                b2 |= 0x1;
            }

            // Third
            int b3 = 0x00;
            if (p.remove(Privilege.ReceiptGeneration)) {
                b3 |= 0x80;
            }
            if (p.remove(Privilege.CipheredLoadFileDataBlock)) {
                b3 |= 0x40;
            }
            if (p.remove(Privilege.ContactlessActivation)) {
                b3 |= 0x20;
            }
            if (p.remove(Privilege.ContactlessSelfActivation)) {
                b3 |= 0x10;
            }
            return new byte[]{(byte) (b1 & 0xFF), (byte) (b2 & 0xFF), (byte) (b3 & 0xFF)};
        }

        public byte toByte() {
            byte[] bytes = toBytes();
            if (bytes.length == 1)
                return bytes[0];
            throw new IllegalStateException("This privileges set can not be encoded in one byte");
        }

        public String toString() {
            return privs.stream().map(i -> i.toString()).collect(Collectors.joining(", "));
        }

        public boolean has(Privilege p) {
            return privs.contains(p);
        }

        public void add(Privilege p) {
            privs.add(p);
        }

        public boolean isEmpty() {
            return privs.size() == 0;
        }

        public int size() {
            return privs.size();
        }
    }
}
