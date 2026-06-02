// SPDX-FileCopyrightText: 2015 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.core.HexUtils;
import pro.javacard.capfile.AID;
import pro.javacard.gp.data.BitField;

import java.util.*;

import static pro.javacard.gp.data.BitField.byte_mask;

// Immutable registry entry - pure data
public record GPRegistryEntryNG(
        AID aid,
        Kind kind,
        int lifecycle,
        Set<Privilege> privileges,
        AID domain,
        AID loadFile,
        byte[] version,
        List<AID> modules,
        Set<Integer> implicitContact,
        Set<Integer> implicitContactless,
        // Contactless activation state (9F70 second byte); present on Amendment C cards only, otherwise null
        Integer state
) {
    public GPRegistryEntryNG {
        // Note: caller assures that privileges are present
        Objects.requireNonNull(privileges);
        // Promote application with SecurityDomain privilege to SecurityDomain kind
        if (kind == Kind.Application && privileges.contains(Privilege.SecurityDomain)) {
            kind = Kind.SecurityDomain;
        }
        // EnumSet iterates in declaration order, so privilege listings are deterministic
        privileges = privileges.isEmpty() ? Set.of() : Collections.unmodifiableSet(EnumSet.copyOf(privileges));
        modules = modules != null ? List.copyOf(modules) : List.of();
        implicitContact = implicitContact != null ? Set.copyOf(implicitContact) : Set.of();
        implicitContactless = implicitContactless != null ? Set.copyOf(implicitContactless) : Set.of();
        if (version != null) {
            version = version.clone();
        }
    }

    @Override
    public byte[] version() {
        return version == null ? null : version.clone();
    }

    @Override
    public Set<Privilege> privileges() {
        return privileges.isEmpty() ? Set.of() : EnumSet.copyOf(privileges);
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

    public boolean hasPrivilege(Privilege p) {
        return privileges.contains(p);
    }

    public Optional<AID> getDomain() {
        return Optional.ofNullable(domain);
    }

    public Optional<AID> getSource() {
        return Optional.ofNullable(loadFile);
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

    public String getLifeCycleString() {
        return switch (kind) {
            case IssuerSecurityDomain -> ByteEnum.fromByte(ISDLifeCycle.class, lifecycle).name();
            case SecurityDomain -> ByteEnum.fromByte(SSDLifeCycle.class, lifecycle).name();
            case ExecutableLoadFile -> ByteEnum.fromByte(PKGLifeCycle.class, lifecycle).name();
            case Application -> ByteEnum.fromByte(APPLifeCycle.class, lifecycle).name();
        };
    }

    @Override
    public String toString() {
        return "%s: %s, %s".formatted(kind.toShortString(), HexUtils.bin2hex(aid.getBytes()), getLifeCycleString());
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof GPRegistryEntryNG o) {
            return o.kind.equals(this.kind) && o.aid.equals(this.aid);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(aid, kind);
    }

    // === Builder ===

    public static class Builder {
        Kind kind;
        AID aid;
        int lifecycle;
        Set<Privilege> privileges = EnumSet.noneOf(Privilege.class);
        AID domain;
        AID loadFile;
        byte[] version;
        List<AID> modules = new ArrayList<>();
        Set<Integer> implicitContact = new HashSet<>();
        Set<Integer> implicitContactless = new HashSet<>();
        Integer state;

        public Builder kind(Kind kind) {
            this.kind = kind;
            return this;
        }

        public Builder aid(AID aid) {
            this.aid = aid;
            return this;
        }

        public Builder lifecycle(int lifecycle) {
            this.lifecycle = lifecycle;
            return this;
        }

        public Builder privileges(Set<Privilege> privileges) {
            this.privileges = EnumSet.copyOf(privileges);
            return this;
        }

        public Builder domain(AID domain) {
            this.domain = domain;
            return this;
        }

        public Builder loadFile(AID loadFile) {
            this.loadFile = loadFile;
            return this;
        }

        public Builder version(byte[] version) {
            this.version = version.clone();
            return this;
        }

        public Builder modules(List<AID> modules) {
            this.modules = new ArrayList<>(modules);
            return this;
        }

        public Builder addModule(AID module) {
            this.modules.add(module);
            return this;
        }

        public Builder addImplicitContact(int v) {
            this.implicitContact.add(v);
            return this;
        }

        public Builder addImplicitContactless(int v) {
            this.implicitContactless.add(v);
            return this;
        }

        public Builder state(int state) {
            this.state = state;
            return this;
        }

        public GPRegistryEntryNG build() {
            return new GPRegistryEntryNG(aid, kind, lifecycle, privileges, domain, loadFile,
                    version, modules, implicitContact, implicitContactless, state);
        }
    }

    // === Enums ===

    public enum Kind {
        IssuerSecurityDomain, Application, SecurityDomain, ExecutableLoadFile;

        public String toShortString() {
            return switch (this) {
                case IssuerSecurityDomain -> "ISD";
                case Application -> "APP";
                case SecurityDomain -> "DOM";
                case ExecutableLoadFile -> "PKG";
            };
        }
    }

    public interface ByteEnum {
        int matchValue();

        default boolean matches(int value) {
            return matchValue() == value;
        }

        static <T extends Enum<T> & ByteEnum> Optional<T> find(Class<T> klass, int value) {
            for (var state : klass.getEnumConstants()) {
                if (state.matches(value)) {
                    return Optional.of(state);
                }
            }
            return Optional.empty();
        }

        static <T extends Enum<T> & ByteEnum> T fromByte(Class<T> klass, int value) {
            return find(klass, value).orElseThrow(() ->
                    new IllegalArgumentException("Unknown %s value: 0x%02X".formatted(klass.getSimpleName(), value & 0xFF)));
        }
    }

    // Application Family (Amendment C tag 87) is the ISO/IEC 14443-3 AFI; the high nibble names the industry sector
    public enum AppFamily implements ByteEnum {
        ANY(0x00), TRANSPORT(0x10), FINANCIAL(0x20), IDENTIFICATION(0x30),
        TELECOMMUNICATION(0x40), MEDICAL(0x50), MULTIMEDIA(0x60), GAMING(0x70), DATA_STORAGE(0x80);

        private final int value;

        AppFamily(int value) {
            this.value = value;
        }

        @Override
        public int matchValue() {
            return value;
        }

        @Override
        public boolean matches(int v) {
            return (v & 0xF0) == value;
        }
    }

    public enum ISDLifeCycle implements ByteEnum {
        OP_READY(0x01), INITIALIZED(0x07), SECURED(0x0F), CARD_LOCKED(0x7F), TERMINATED(0xFF);

        private final int value;

        ISDLifeCycle(final int value) {
            this.value = value;
        }

        @Override
        public int matchValue() {
            return value;
        }

        public int getValue() {
            return value;
        }
    }

    public enum SSDLifeCycle implements ByteEnum {
        INSTALLED(0x03), SELECTABLE(0x07), PERSONALIZED(0x0F), LOCKED(0x83);

        private final int value;

        SSDLifeCycle(int value) {
            this.value = value;
        }

        @Override
        public int matchValue() {
            return value;
        }

        @Override
        public boolean matches(int v) {
            return this == LOCKED ? (v & 0x83) == 0x83 : v == value;
        }
    }

    public enum APPLifeCycle implements ByteEnum {
        INSTALLED(0x03), SELECTABLE(0x07), LOCKED(0x83);

        private final int value;

        APPLifeCycle(int value) {
            this.value = value;
        }

        @Override
        public int matchValue() {
            return value;
        }

        @Override
        public boolean matches(int v) {
            return switch (this) {
                case INSTALLED -> v == 0x03;
                case SELECTABLE -> (v & 0xFF) <= 0x7F;
                case LOCKED -> (v & 0x83) == 0x83;
            };
        }
    }

    public enum PKGLifeCycle implements ByteEnum {
        LOADED(0x01), LOGICALLY_DELETED(0x00);

        private final int value;

        PKGLifeCycle(int value) {
            this.value = value;
        }

        @Override
        public int matchValue() {
            return value;
        }
    }

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
        RFU(new Def.RFU(byte_mask(2, 0x7)));

        private final Def def;

        Privilege(Def def) {
            this.def = def;
        }

        @Override
        public Def def() {
            return def;
        }

        public static Optional<Privilege> lookup(String name) {
            return Arrays.stream(values()).filter(e -> e.name().equalsIgnoreCase(name)).findFirst();
        }
    }
}
