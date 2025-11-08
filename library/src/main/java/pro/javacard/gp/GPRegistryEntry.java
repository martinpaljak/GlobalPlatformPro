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
import pro.javacard.capfile.AID;
import pro.javacard.gp.data.BitField;

import java.util.*;
import java.util.function.Predicate;

import static pro.javacard.gp.data.BitField.byte_mask;

public class GPRegistryEntry {

    GPRegistryEntry() {
    }

    AID aid;
    byte lifecycle;
    Kind kind; // domain, application, capfile
    AID domain; // associated security domain

    // Apps and Domains
    private final EnumSet<Privilege> privileges = EnumSet.noneOf(Privilege.class);
    private AID from;

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

    public Optional<AID> getSource() {
        return Optional.ofNullable(from);
    }

    void setLoadFile(AID aid) {
        this.from = aid;
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

    public interface ByteEnum {
        default Predicate<Byte> matcher() {
            return p -> true;
        }

        static <T extends Enum<T> & ByteEnum> T fromByte(Class<T> klass, byte value) {
            for (var state : klass.getEnumConstants()) {
                if (state.matcher().test(value)) {
                    return state;
                }
            }
            throw new IllegalArgumentException("Unknown %s value: 0x%02X".formatted(klass.getSimpleName(), value & 0xFF));
        }
    }


    public enum ISDLifeCycle implements ByteEnum {
        OP_READY(0x01),
        INITIALIZED(0x07),
        SECURED(0x0F),
        CARD_LOCKED(0x7F),
        TERMINATED(0xFF);

        private final byte value;

        ISDLifeCycle(int value) {
            this.value = (byte) (value & 0xFF);
        }

        @Override
        public Predicate<Byte> matcher() {
            return v -> v == value;
        }

        public byte getValue() {
            return (byte) ordinal();
        }
    }

    public enum SSDLifeCycle implements ByteEnum {
        // GP 2.2.1 Table 11-5
        INSTALLED(v -> v == 0x03),
        SELECTABLE(v -> v == 0x07),
        PERSONALIZED(v -> v == 0x0F),
        LOCKED(v -> (v & 0x83) == 0x83);

        private final Predicate<Byte> matcher;

        SSDLifeCycle(Predicate<Byte> matcher) {
            this.matcher = matcher;
        }

        @Override
        public Predicate<Byte> matcher() {
            return matcher;
        }
    }

    public enum APPLifeCycle implements ByteEnum {
        INSTALLED(v -> v == 0x03),
        SELECTABLE(v -> (v & 0xFF) <= 0x7F),
        LOCKED(v -> (v & 0x83) == 0x83);

        private final Predicate<Byte> matcher;

        APPLifeCycle(Predicate<Byte> matcher) {
            this.matcher = matcher;
        }

        @Override
        public Predicate<Byte> matcher() {
            return matcher;
        }
    }

    public enum PKGLifeCycle implements ByteEnum {
        // GP 2.2.1 Table 11-3
        LOADED(v -> v == 0x01),
        LOGICALLY_DELETED(v -> v == 0x00);

        private final Predicate<Byte> matcher;

        PKGLifeCycle(Predicate<Byte> matcher) {
            this.matcher = matcher;
        }

        @Override
        public Predicate<Byte> matcher() {
            return matcher;
        }
    }

    public AID getAID() {
        return aid;
    }

    void setAID(AID aid) {
        this.aid = aid;
    }

    public Optional<AID> getDomain() {
        return Optional.ofNullable(domain);
    }

    public byte getLifeCycle() {
        return lifecycle;
    }

    void setLifeCycle(byte lifecycle) {
        this.lifecycle = lifecycle;
    }

    public Kind getType() {
        return kind;
    }

    void setType(Kind type) {
        this.kind = type;
    }

    public boolean isPackage() {
        return kind == Kind.PKG;
    }

    public boolean isApplet() {
        return kind == Kind.APP;
    }

    public boolean isDomain() {
        return kind == Kind.SSD || kind == Kind.ISD;
    }

    void setDomain(AID dom) {
        this.domain = dom;
    }

    public String toString() {
        return String.format("%s: %s, %s", kind, HexUtils.bin2hex(aid.getBytes()), getLifeCycleString());
    }

    public String getLifeCycleString() {
        if (kind == Kind.ISD) {
            return ByteEnum.fromByte(ISDLifeCycle.class, lifecycle).name();
        } else if (kind == Kind.SSD) {
            return ByteEnum.fromByte(SSDLifeCycle.class, lifecycle).name();
        } else if (kind == Kind.PKG) {
            return ByteEnum.fromByte(PKGLifeCycle.class, lifecycle).name();
        } else {
            return ByteEnum.fromByte(APPLifeCycle.class, lifecycle).name();
        }
    }

    public Set<Integer> getImplicitlySelectedContact() {
        return Collections.unmodifiableSet(implicitContact);
    }

    public Set<Integer> getImplicitlySelectedContactless() {
        return Collections.unmodifiableSet(implicitContactless);
    }

    public enum Kind {ISD, APP, SSD, PKG}

    // See GP 2.2.1 11.1.2 Tables 11-7, 11-8, 11-9
    // See GP 2.1.1 Table 9-7 (matches 2.2 Table 11-7)
    public enum Privilege implements BitField<Privilege> {
        // 1st byte
        SecurityDomain(byte_mask(0, 0x80)),
        DAPVerification(byte_mask(0, 0xC0)),
        DelegatedManagement(byte_mask(0, 0xA0)),
        CardLock(byte_mask(0, 0x10)),
        CardTerminate(byte_mask(0, 0x8)),
        CardReset(byte_mask(0, 0x4)),
        CVMManagement(byte_mask(0, 0x2)),
        MandatedDAPVerification(byte_mask(0, 0xC1)),
        // 2nd byte
        TrustedPath(byte_mask(1, 0x80)),
        AuthorizedManagement(byte_mask(1, 0x40)),
        TokenVerification(byte_mask(1, 0x20)),
        GlobalDelete(byte_mask(1, 0x10)),
        GlobalLock(byte_mask(1, 0x8)),
        GlobalRegistry(byte_mask(1, 0x4)),
        FinalApplication(byte_mask(1, 0x2)),
        GlobalService(byte_mask(1, 0x1)),
        // 3rd byte
        ReceiptGeneration(byte_mask(2, 0x80)),
        CipheredLoadFileDataBlock(byte_mask(2, 0x40)),
        ContactlessActivation(byte_mask(2, 0x20)),
        ContactlessSelfActivation(byte_mask(2, 0x10)),
        PrivacyTrusted(byte_mask(2, 0x8)),
        // Last 3 bits RFU
        RFU(new Def.RFU(byte_mask(2, 0x7)));

        private final Def def;

        Privilege(Def def) {
            this.def = def;
        }

        public static Optional<Privilege> lookup(String v) {
            return Arrays.stream(values()).filter(e -> e.name().equalsIgnoreCase(v)).findFirst();
        }

        public static Set<Privilege> fromBytes(byte[] v) {
            if (v.length != 1 && v.length != 3) {
                throw new IllegalArgumentException("Privileges must be encoded on 1 or 3 bytes: " + HexUtils.bin2hex(v));
            }
            var r = BitField.parse(Privilege.class, v);
            if (r.contains(Privilege.RFU)) {
                throw new GPDataException("RFU bits set in privileges", v);
            }
            return r;
        }

        public static Set<Privilege> fromByte(byte v) {
            return fromBytes(new byte[]{v});
        }

        public static byte[] toBytes(Set<Privilege> privs) {
            return BitField.toBytes(EnumSet.copyOf(privs), 3);
        }

        @Override
        public Def def() {
            return def;
        }
    }
}
