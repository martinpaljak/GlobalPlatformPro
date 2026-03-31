/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2026-present Martin Paljak, martin@martinpaljak.net
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
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
package pro.javacard.gp.ng;

import pro.javacard.capfile.AID;
import pro.javacard.gp.GPDataException;
import pro.javacard.gp.data.BitField;
import pro.javacard.gp.ng.GPRegistryEntryNG.Kind;
import pro.javacard.gp.ng.GPRegistryEntryNG.Privilege;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import java.util.*;
import java.util.stream.Stream;

// Immutable registry snapshot - record for value semantics
public record GPRegistryNG(List<GPRegistryEntryNG> entries) implements Iterable<GPRegistryEntryNG> {

    // Dedup key - correct equality, no hash collisions
    private record Key(AID aid, Kind kind) {
    }

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

        for (TLV t : TLV.findAll(tlvs, Tag.ber(0xE3))) {
            if (!t.hasChildren()) {continue;}

            var b = new GPRegistryEntryNG.Builder().kind(type);

            var aidTag = t.find(Tag.ber(0x4F));
            if (aidTag != null) {
                b.aid(new AID(aidTag.value()));
            }

            var lcTag = t.find(Tag.ber(0x9F, 0x70));
            if (lcTag != null) {
                b.lifecycle(lcTag.value()[0] & 0xFF);
            }

            var privTag = t.find(Tag.ber(0xC5));
            if (privTag != null) {
                b.privileges(BitField.parse(Privilege.class, privTag.value(), 1, 3));
            }

            // GP 2.3 11.1.7 - implicit selection
            for (TLV cf : t.findAll(Tag.ber(0xCF))) {
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

            var loadFileTag = t.find(Tag.ber(0xC4));
            if (loadFileTag != null) {
                b.loadFile(new AID(loadFileTag.value()));
            }

            var versionTag = t.find(Tag.ber(0xCE));
            if (versionTag != null) {
                b.version(versionTag.value());
            }

            for (TLV lf : t.findAll(Tag.ber(0x84))) {
                b.addModule(new AID(lf.value()));
            }

            var domainTag = t.find(Tag.ber(0xCC));
            if (domainTag != null) {
                b.domain(new AID(domainTag.value()));
            }

            // APP->SSD promotion handled by record compact constructor
            result.add(b.build());
        }
        return List.copyOf(result);
    }
}
