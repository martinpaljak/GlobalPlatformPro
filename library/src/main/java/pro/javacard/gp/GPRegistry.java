// SPDX-FileCopyrightText: 2016 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2009 Wojciech Mostowski <woj@cs.ru.nl>
// SPDX-FileCopyrightText: 2009 Francois Kooman <F.Kooman@student.science.ru.nl>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.data.BitField;
import pro.javacard.tlv.TLV;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.function.BinaryOperator;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public final class GPRegistry implements Iterable<GPRegistryEntry> {
    private static final Logger logger = LoggerFactory.getLogger(GPRegistry.class);

    public GPRegistry() {}

    final ArrayList<GPRegistryEntry> entries = new ArrayList<>();

    public void add(final GPRegistryEntry entry) {
        // "fix" the kind at a single location.
        if (entry.hasPrivilege(Privilege.SecurityDomain) && entry.getType() == Kind.APP) {
            entry.setType(Kind.SSD);
        }
        if (!entries.contains(entry)) {
            entries.add(entry);
        } else {
            // We populate the package with applets if card returns them, so not an error
            if (entry.getType() != Kind.PKG) {
                logger.warn("Registry already contains {}", entry);
            }
        }
    }

    // All children of this domain
    public List<GPRegistryEntry> byDomain(final AID domain) {
        return entries.stream().filter(e -> e.getDomain().equals(Optional.of(domain))).toList();
    }

    // Entry with existing applet
    public Optional<GPRegistryEntry> byModule(final AID applet) {
        return entries.stream().filter(e -> e.getModules().contains(applet)).findFirst();
    }

    @Override
    public Iterator<GPRegistryEntry> iterator() {
        return entries.iterator();
    }

    public List<GPRegistryEntry> allPackages() {
        return entries.stream().filter(GPRegistryEntry::isPackage).collect(Collectors.toList());
    }

    public List<AID> allPackageAIDs() {
        return allPackages().stream().map(GPRegistryEntry::getAID).collect(Collectors.toList());
    }

    public List<AID> allAppletAIDs() {
        return allApplets().stream().map(GPRegistryEntry::getAID).collect(Collectors.toList());
    }

    public List<AID> allAIDs() {
        return entries.stream().map(GPRegistryEntry::getAID).collect(Collectors.toList());
    }

    public Optional<GPRegistryEntry> getDomain(AID aid) {
        return allDomains().stream().filter(e -> e.aid.equals(aid)).reduce(onlyOne());
    }

    public List<GPRegistryEntry> allApplets() {
        return entries.stream().filter(GPRegistryEntry::isApplet).collect(Collectors.toList());
    }

    public List<GPRegistryEntry> allDomains() {
        return entries.stream().filter(GPRegistryEntry::isDomain).collect(Collectors.toList());
    }

    public Optional<AID> getDefaultSelectedAID() {
        return allApplets().stream().filter(e -> e.hasPrivilege(Privilege.CardReset)).map(GPRegistryEntry::getAID)
                .reduce(onlyOne());
    }

    public Optional<AID> getDefaultSelectedPackageAID() {
        return getDefaultSelectedAID().flatMap(aid -> allPackages().stream()
                .filter(e -> e.getModules().contains(aid))
                .map(GPRegistryEntry::getAID).reduce(onlyOne()));
    }

    // Shorthand
    public Optional<GPRegistryEntry> getISD() {
        // Could be empty if registry is a view from SSD
        return allDomains().stream().filter(e -> e.getType() == Kind.ISD).reduce(onlyOne());
    }

    private void populate_legacy(final int p1, final byte[] data, final Kind type, final GPCardProfile spec) throws GPDataException {
        var offset = 0;
        try {
            while (offset < data.length) {
                var len = data[offset++] & 0xFF;
                var aid = new AID(data, offset, len);
                offset += len;
                final byte lifecycle = data[offset++];
                final byte privileges = data[offset++];
                final var e = new GPRegistryEntry();

                if (type == Kind.ISD || type == Kind.APP) {
                    e.setType(type);
                    e.setAID(aid);
                    e.setPrivileges(BitField.parse(Privilege.class, new byte[] { privileges }, 1, 3));
                    e.setLifeCycle(lifecycle);
                } else if (type == Kind.PKG) {
                    if (privileges != 0x00) {
                        throw new GPDataException(
                                "Privileges of Load File is not 0x00 but %02X".formatted(privileges & 0xFF));
                    }
                    e.setAID(aid);
                    e.setLifeCycle(lifecycle);
                    e.setType(type);
                    // Modules. 0x20 is load files, 0x10 load files with modules
                    if (spec.doesReportModules() && p1 != 0x20) {
                        final var num = data[offset++];
                        for (var i = 0; i < num; i++) {
                            len = data[offset++] & 0xFF;
                            aid = new AID(data, offset, len);
                            offset += len;
                            e.addModule(aid);
                        }
                    }
                }
                add(e);
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new GPDataException("Invalid response to GET STATUS", e);
        }
    }

    private void populate_tags(final byte[] data, final Kind type) throws GPDataException {
        final var tlvs = TLV.parse(data);
        GPUtils.trace_tlv(data, logger);

        for (TLV t : tlvs.findAll(0xE3)) {
            final var e = new GPRegistryEntry();
            if (t.hasChildren()) {
                t.find(0x4f).ifPresent(aid -> e.setAID(new AID(aid.value())));
                t.find(0x9F70).ifPresent(lc -> e.setLifeCycle(lc.value()[0]));
                t.find(0xC5).ifPresent(privs -> e.setPrivileges(BitField.parse(Privilege.class, privs.value(), 1, 3)));

                // 11.1.7 of GPC 2.3
                for (TLV cf : t.findAll(0xCF)) {
                    final var cfb = cf.value();
                    if (cfb.length != 1) {
                        throw new GPDataException("Tag CF not single byte", cfb);
                    }
                    final var v = cfb[0] & 0xFF;
                    final var c = v & 0x1F;
                    if ((v & 0x80) == 0x80) {
                        e.implicitContactless.add(c);
                    } else if ((v & 0x40) == 0x40) {
                        e.implicitContact.add(c);
                    }
                }

                t.find(0xC4).ifPresent(loadfile -> e.setLoadFile(new AID(loadfile.value())));
                t.find(0xCE).ifPresent(version -> e.setVersion(version.value()));

                for (TLV lf : t.findAll(0x84)) {
                    e.addModule(new AID(lf.value()));
                }

                t.find(0xCC).ifPresent(domain -> e.setDomain(new AID(domain.value())));
            }
            e.setType(type);
            add(e);
        }
    }

    // TODO: remove with new parser
    public void parse_and_populate(final int p1, final byte[] data, final Kind type, final GPCardProfile profile) throws GPDataException {
        if (profile.getStatusUsesTags()) {
            populate_tags(data, type);
        } else {
            populate_legacy(p1, data, type, profile);
        }
    }

    public static <T> BinaryOperator<T> onlyOne() {
        return onlyOne(() -> new GPException("Expected only one"));
    }

    public static <T, E extends RuntimeException> BinaryOperator<T> onlyOne(final Supplier<E> exception) {
        return (e, o) -> {
            throw exception.get();
        };
    }
}
