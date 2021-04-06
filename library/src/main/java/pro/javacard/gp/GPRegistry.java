/*
 * gpj - Global Platform for Java SmartCardIO
 *
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
 *
 */

package pro.javacard.gp;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.AID;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.function.BinaryOperator;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class GPRegistry implements Iterable<GPRegistryEntry> {
    private static final Logger logger = LoggerFactory.getLogger(GPRegistry.class);
    ArrayList<GPRegistryEntry> entries = new ArrayList<>();

    public void add(GPRegistryEntry entry) {
        // "fix" the kind at a single location.
        if (entry.hasPrivilege(Privilege.SecurityDomain) && entry.getType() == Kind.Application) {
            entry.setType(Kind.SecurityDomain);
        }
        if (!entries.contains(entry)) {
            entries.add(entry);
        } else {
            // We populate the package with applets if card returns them, so not an error
            if (entry.getType() != Kind.ExecutableLoadFile)
                logger.warn("Registry already contains {}", entry);
        }
    }

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
        return allApplets().stream().filter(e -> e.hasPrivilege(Privilege.CardReset)).map(GPRegistryEntry::getAID).reduce(onlyOne());
    }

    public Optional<AID> getDefaultSelectedPackageAID() {
        Optional<AID> defaultAID = getDefaultSelectedAID();
        if (defaultAID.isPresent()) {
            return allPackages().stream().filter(e -> e.getModules().contains(defaultAID.get())).map(GPRegistryEntry::getAID).reduce(onlyOne());
        }
        return defaultAID;
    }

    // Shorthand
    public Optional<GPRegistryEntry> getISD() {
        // Could be empty if registry is a view from SSD
        return allDomains().stream().filter(e -> e.getType() == Kind.IssuerSecurityDomain).reduce(onlyOne());
    }

    private void populate_legacy(int p1, byte[] data, Kind type, GPCardProfile spec) throws GPDataException {
        int offset = 0;
        try {
            while (offset < data.length) {
                int len = data[offset++];
                AID aid = new AID(data, offset, len);
                offset += len;
                int lifecycle = (data[offset++] & 0xFF);
                byte privileges = data[offset++];
                GPRegistryEntry e = new GPRegistryEntry();

                if (type == Kind.IssuerSecurityDomain || type == Kind.Application) {
                    e.setType(type);
                    e.setAID(aid);
                    e.getPrivileges().addAll(Privilege.fromBytes(new byte[]{privileges}));
                    e.setLifeCycle(lifecycle);
                } else if (type == Kind.ExecutableLoadFile) {
                    if (privileges != 0x00) {
                        throw new GPDataException(String.format("Privileges of Load File is not 0x00 but %02X", privileges & 0xFF));
                    }
                    e.setAID(aid);
                    e.setLifeCycle(lifecycle);
                    e.setType(type);
                    // Modules. 0x20 is load files, 0x10 load files with modules
                    if (spec.doesReportModules() && p1 != 0x20) {
                        int num = data[offset++];
                        for (int i = 0; i < num; i++) {
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

    private void populate_tags(byte[] data, Kind type) throws GPDataException {
        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(data);
        GPUtils.trace_tlv(data, logger);

        for (BerTlv t : tlvs.findAll(new BerTag(0xE3))) {
            GPRegistryEntry e = new GPRegistryEntry();
            if (t.isConstructed()) {
                BerTlv aid = t.find(new BerTag(0x4f));
                if (aid != null) {
                    AID aidv = new AID(aid.getBytesValue());
                    e.setAID(aidv);
                }
                BerTlv lifecycletag = t.find(new BerTag(0x9F, 0x70));
                if (lifecycletag != null) {
                    e.setLifeCycle(lifecycletag.getBytesValue()[0] & 0xFF);
                }

                BerTlv privstag = t.find(new BerTag(0xC5));
                if (privstag != null) {
                    e.setPrivileges(Privilege.fromBytes(privstag.getBytesValue()));
                }

                // 11.1.7 of GPC 2.3
                for (BerTlv cf : t.findAll(new BerTag(0xCF))) {
                    byte[] cfb = cf.getBytesValue();
                    if (cfb.length != 1)
                        throw new GPDataException("Tag CF not single byte", cfb);
                    int v = cfb[0] & 0xFF;
                    int c = v & 0x1F;
                    if ((v & 0x80) == 0x80) {
                        e.implicitContactless.add(c);
                    } else if ((v & 0x40) == 0x40) {
                        e.implicitContact.add(c);
                    }
                }

                BerTlv loadfiletag = t.find(new BerTag(0xC4));
                if (loadfiletag != null) {
                    e.setLoadFile(new AID(loadfiletag.getBytesValue()));
                }
                BerTlv versiontag = t.find(new BerTag(0xCE));
                if (versiontag != null) {
                    e.setVersion(versiontag.getBytesValue());
                }

                for (BerTlv lf : t.findAll(new BerTag(0x84))) {
                    e.addModule(new AID(lf.getBytesValue()));
                }

                BerTlv domaintag = t.find(new BerTag(0xCC));
                if (domaintag != null) {
                    e.setDomain(new AID(domaintag.getBytesValue()));
                }
            }
            e.setType(type);
            add(e);
        }
    }

    void parse_and_populate(int p1, byte[] data, Kind type, GPCardProfile profile) throws GPDataException {
        if (profile.getStatusUsesTags()) {
            populate_tags(data, type);
        } else {
            populate_legacy(p1, data, type, profile);
        }
    }

    public static <T> BinaryOperator<T> onlyOne() {
        return onlyOne(() -> new GPException("Expected only one "));
    }

    public static <T, E extends RuntimeException> BinaryOperator<T> onlyOne(Supplier<E> exception) {
        return (e, o) -> {
            throw exception.get();
        };
    }
}
