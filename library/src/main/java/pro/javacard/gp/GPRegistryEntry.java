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

import apdu4j.core.HexUtils;
import pro.javacard.AID;

import java.util.*;

public class GPRegistryEntry {

    AID aid;
    int lifecycle;
    Kind kind;
    AID domain; // Associated security domain

    // Apps and Domains
    private final EnumSet<Privilege> privileges = EnumSet.noneOf(Privilege.class);
    private AID loadfile; // source

    // Packages
    private byte[] version;
    private final List<AID> modules = new ArrayList<>();

    HashSet<Integer> implicitContact = new HashSet<>();
    HashSet<Integer> implicitContactless = new HashSet<>();

    public Set<Privilege> getPrivileges() {
        return Collections.unmodifiableSet(privileges);
    }

    void setPrivileges(Set<Privilege> privs) {
        privileges.addAll(privs);
    }

    public AID getLoadFile() {
        return loadfile;
    }

    public void setLoadFile(AID aid) {
        this.loadfile = aid;
    }

    public boolean hasPrivilege(Privilege p) {
        return privileges.contains(p);
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
            return (version[0] & 0xFF) + "." + (version[1] & 0xFF);
        }
        return "<unknown format " + HexUtils.bin2hex(version) + ">";
    }

    public void addModule(AID aid) {
        modules.add(aid);
    }

    public List<AID> getModules() {
        return new ArrayList<>(modules);
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
                    return "LOGICALLY_DELETED"; // From OP201
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
        return String.format("%s: %s, %s", kind.toShortString(), HexUtils.bin2hex(aid.getBytes()), getLifeCycleString());
    }

    public String getLifeCycleString() {
        return getLifeCycleString(kind, lifecycle);
    }

    public Set<Integer> getImplicitlySelectedContact() {
        return Collections.unmodifiableSet(implicitContact);
    }

    public Set<Integer> getImplicitlySelectedContactless() {
        return Collections.unmodifiableSet(implicitContactless);
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

    // See GP 2.2.1 11.1.2 Tables 11-7, 11-8, 11-9
    // See GP 2.1.1 Table 9-7 (matches 2.2 Table 11-7)
    public enum Privilege {
        SecurityDomain(0x80, 0),
        DAPVerification(0xC0, 0),
        DelegatedManagement(0xA0, 0),
        CardLock(0x10, 0),
        CardTerminate(0x8, 0),
        CardReset(0x4, 0),
        CVMManagement(0x2, 0),
        MandatedDAPVerification(0xC1, 0),
        TrustedPath(0x80, 1),
        AuthorizedManagement(0x40, 1),
        TokenVerification(0x20, 1),
        GlobalDelete(0x10, 1),
        GlobalLock(0x8, 1),
        GlobalRegistry(0x4, 1),
        FinalApplication(0x2, 1),
        GlobalService(0x1, 1),
        ReceiptGeneration(0x80, 2),
        CipheredLoadFileDataBlock(0x40, 2),
        ContactlessActivation(0x20, 2),
        ContactlessSelfActivation(0x10, 2);

        int value;
        int pos;

        Privilege(int value, int pos) {
            this.value = value;
            this.pos = pos;
        }

        public static Optional<Privilege> lookup(String v) {
            return Arrays.stream(values()).filter(e -> e.name().equalsIgnoreCase(v)).findFirst();
        }

        public static Set<Privilege> fromBytes(byte[] v) {
            if (v.length != 1 && v.length != 3) {
                throw new IllegalArgumentException("Privileges must be encoded on 1 or 3 bytes: " + HexUtils.bin2hex(v));
            }
            if (v.length == 3 && (v[2] & 0x0F) != 0x00) {
                // RFU
                throw new GPDataException("RFU bits set in privileges", v);
            }

            LinkedHashSet<Privilege> r = new LinkedHashSet<>();
            for (int i = 0; i < v.length; i++) {
                final int p = i;
                Arrays.stream(values()).filter(e -> e.pos == p).forEach(e -> {
                    if (e.value == (e.value & v[p]))
                        r.add(e);
                });
            }
            return r;
        }

        static boolean isOneByte(Set<Privilege> privs) {
            return privs.stream().noneMatch(e -> e.pos != 0);
        }

        public static byte[] toBytes(Set<Privilege> privs) {
            byte[] r = new byte[3];
            for (Privilege p : privs) {
                r[p.pos] |= p.value;
            }
            return r;
        }

        public static byte[] toByteOrBytes(Set<Privilege> privs) {
            byte[] r = toBytes(privs);
            if (isOneByte(privs))
                r = Arrays.copyOf(r, 1);
            return r;
        }

        public static byte toByte(Set<Privilege> privs) {
            if (!isOneByte(privs))
                throw new IllegalStateException("This privileges set can not be encoded in one byte");
            return toBytes(privs)[0];
        }
    }
}
