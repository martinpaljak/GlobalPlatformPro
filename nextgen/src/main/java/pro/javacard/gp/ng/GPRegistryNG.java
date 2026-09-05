// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import pro.javacard.capfile.AID;
import pro.javacard.gp.GPDataException;
import pro.javacard.gp.data.BitField;
import pro.javacard.gp.ng.GPRegistryEntryNG.Kind;
import pro.javacard.gp.ng.GPRegistryEntryNG.Privilege;
import pro.javacard.tlv.TLV;

import java.util.*;
import java.util.stream.Stream;

// Immutable registry snapshot - record for value semantics
public record GPRegistryNG(List<GPRegistryEntryNG> entries) implements Iterable<GPRegistryEntryNG> {

    // Dedup key - correct equality, no hash collisions
    private record Key(AID aid, Kind kind) {}

    public GPRegistryNG {
        // Deduplicate by (kind, aid) - last writer wins, preserves insertion order
        var seen = new LinkedHashMap<Key, GPRegistryEntryNG>();
        for (var e : entries) {
            seen.put(new Key(e.aid(), e.kind()), e);
        }
        entries = List.copyOf(seen.values());
    }

    @Override
    public Iterator<GPRegistryEntryNG> iterator() {
        return entries.iterator();
    }

    public Stream<GPRegistryEntryNG> stream() {
        return entries.stream();
    }

    public int size() {
        return entries.size();
    }

    public boolean isEmpty() {
        return entries.isEmpty();
    }

    // Merge two registries
    public GPRegistryNG merge(GPRegistryNG other) {
        return new GPRegistryNG(Stream.concat(stream(), other.stream()).toList());
    }

    // Merge with a list
    public GPRegistryNG merge(List<GPRegistryEntryNG> more) {
        return new GPRegistryNG(Stream.concat(stream(), more.stream()).toList());
    }

    public static GPRegistryNG empty() {
        return new GPRegistryNG(List.of());
    }

    // === Queries ===

    public List<GPRegistryEntryNG> allApplets() {
        return stream().filter(GPRegistryEntryNG::isApplet).toList();
    }

    public List<GPRegistryEntryNG> allPackages() {
        return stream().filter(GPRegistryEntryNG::isPackage).toList();
    }

    public List<GPRegistryEntryNG> allDomains() {
        return stream().filter(GPRegistryEntryNG::isDomain).toList();
    }

    public List<GPRegistryEntryNG> byDomain(AID domain) {
        return stream().filter(e -> e.getDomain().equals(Optional.of(domain))).toList();
    }

    public Optional<GPRegistryEntryNG> byModule(AID applet) {
        return stream().filter(e -> e.modules().contains(applet)).findFirst();
    }

    public Optional<GPRegistryEntryNG> getDomain(AID aid) {
        return stream().filter(GPRegistryEntryNG::isDomain).filter(e -> e.aid().equals(aid)).findFirst();
    }

    public Optional<GPRegistryEntryNG> getISD() {
        return stream().filter(e -> e.kind() == Kind.IssuerSecurityDomain).findFirst();
    }

    public Optional<AID> getDefaultSelectedAID() {
        return stream().filter(GPRegistryEntryNG::isApplet).filter(e -> e.hasPrivilege(Privilege.CardReset))
                .map(GPRegistryEntryNG::aid).findFirst();
    }

    // === Pure parsers ===

    // Parse TLV-format GET STATUS response into entries
    public static List<GPRegistryEntryNG> parseTLV(byte[] data, Kind type) {
        var tlvs = TLV.parse(data);
        var result = new ArrayList<GPRegistryEntryNG>();

        for (var t : tlvs.findAll(0xE3)) {
            if (!t.hasChildren()) {
                continue;
            }

            var b = new GPRegistryEntryNG.Builder().kind(type);

            t.find(0x4F).ifPresent(aidTag -> b.aid(new AID(aidTag.value())));
            t.find(0x9F70).ifPresent(lcTag -> {
                var lc = lcTag.value();
                b.lifecycle(lc[0] & 0xFF);
                // Amendment C: second byte of 9F70 carries the contactless activation state
                if (lc.length >= 2) {
                    b.state(lc[1] & 0xFF);
                }
            });
            t.find(0xC5).ifPresent(privTag -> b.privileges(BitField.parse(Privilege.class, privTag.value(), 1, 3)));

            // GP 2.3 11.1.7 - implicit selection
            for (var cf : t.findAll(0xCF)) {
                var cfb = cf.value();
                if (cfb.length != 1) {
                    throw new GPDataException("Tag CF not single byte", cfb);
                }
                var v = cfb[0] & 0xFF;
                var c = v & 0x1F;
                if ((v & 0x80) == 0x80) {
                    b.addImplicitContactless(c);
                } else if ((v & 0x40) == 0x40) {
                    b.addImplicitContact(c);
                }
            }

            t.find(0xC4).ifPresent(loadFileTag -> b.loadFile(new AID(loadFileTag.value())));
            t.find(0xCE).ifPresent(versionTag -> b.version(versionTag.value()));

            for (var lf : t.findAll(0x84)) {
                b.addModule(new AID(lf.value()));
            }

            t.find(0xCC).ifPresent(domainTag -> b.domain(new AID(domainTag.value())));

            // APP->SSD promotion handled by record compact constructor
            result.add(b.build());
        }
        return List.copyOf(result);
    }
}
