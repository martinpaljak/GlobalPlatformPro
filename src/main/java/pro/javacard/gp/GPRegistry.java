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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;

import apdu4j.HexUtils;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPRegistryEntry.Privileges;
import pro.javacard.gp.GlobalPlatform.GPSpec;

/**
 * Convenience class managing a vector of {@link GPRegistryEntry
 * AIDRegistryEntries} with search functionality.
 *
 * Implements {@code Iterable<GPRegistryEntry} to permit foreach loops such as
 * {@code for(GPRegistryEntry e : registry) ...}.
 */
public class GPRegistry implements Iterable<GPRegistryEntry> {
	private static Logger logger = LoggerFactory.getLogger(GPRegistry.class);
	boolean tags = true; // XXX (visibility) true if newer tags format should be used for parsing, false otherwise
	LinkedHashMap<AID, GPRegistryEntry> entries = new LinkedHashMap<AID, GPRegistryEntry>();

	/**
	 * Add one entry to this registry.
	 *
	 * @param entry
	 */
	public void add(GPRegistryEntry entry) {
		// "fix" the kind at a single location.
		if (entry instanceof GPRegistryEntryApp) {
			GPRegistryEntryApp app = (GPRegistryEntryApp) entry;
			if (app.getPrivileges().has(Privilege.SecurityDomain) && entry.getType() == Kind.Application) {
				entry.setType(Kind.SecurityDomain);
			}
		}
		// XXX Legacy, combined with logic in GlobalPlatform.getStatus()
		GPRegistryEntry existing = entries.get(entry.getAID());
		if (existing != null && existing.getType() != entry.getType()) {
			// OP201 cards list the ISD AID as load file.
			return;
		}
		entries.put(entry.getAID(), entry);
	}

	/**
	 * Returns an iterator that iterates over all entries in this registry.
	 *
	 * @return iterator
	 */
	public Iterator<GPRegistryEntry> iterator() {
		return entries.values().iterator();
	}


	/**
	 * Returns a list of all packages in this registry.
	 *
	 * @return a list of all packages
	 */
	public List<GPRegistryEntryPkg> allPackages() {
		List<GPRegistryEntryPkg> res = new ArrayList<GPRegistryEntryPkg>();
		for (GPRegistryEntry e : entries.values()) {
			if (e.isPackage()) {
				res.add((GPRegistryEntryPkg)e);
			}
		}
		return res;
	}

	public List<AID> allPackageAIDs() {
		List<AID> res = new ArrayList<AID>();
		for (GPRegistryEntry e : entries.values()) {
			if (e.isPackage()) {
				res.add(e.getAID());
			}
		}
		return res;
	}
	public List<AID> allAppletAIDs() {
		List<AID> res = new ArrayList<AID>();
		for (GPRegistryEntry e : entries.values()) {
			if (e.isApplet()) {
				res.add(e.getAID());
			}
		}
		return res;
	}
	public List<AID> allAIDs() {
		List<AID> res = new ArrayList<AID>();
		for (GPRegistryEntry e : entries.values()) {
			res.add(e.getAID());
		}
		return res;
	}
	/**
	 * Returns a list of all applets in this registry.
	 *
	 * @return a list of all applets
	 */
	public List<GPRegistryEntryApp> allApplets() {
		List<GPRegistryEntryApp> res = new ArrayList<GPRegistryEntryApp>();
		for (GPRegistryEntry e : entries.values()) {
			if (e.isApplet()) {
				res.add((GPRegistryEntryApp)e);
			}
		}
		return res;
	}

	public AID getDefaultSelectedAID() {
		for (GPRegistryEntryApp e : allApplets()) {
			if (e.getPrivileges().has(Privilege.CardReset)) {
				return e.getAID();
			}
		}
		return null;
	}

	public AID getDefaultSelectedPackageAID() {
		AID defaultAID = getDefaultSelectedAID();
		if (defaultAID != null) {
			for (GPRegistryEntryPkg e : allPackages()) {
				if (e.getModules().contains(defaultAID))
					return e.getAID();
			}
			// Did not get a hit. Loop packages and look for prefixes
			for (GPRegistryEntryPkg e : allPackages()) {
				if (defaultAID.toString().startsWith(e.getAID().toString()))
					return e.getAID();
			}
		}
		return null;
	}

	// Shorthand
	public GPRegistryEntryApp getISD() {
		for (GPRegistryEntryApp a: allApplets()) {
			if (a.getType() == Kind.IssuerSecurityDomain) {
				return a;
			}
		}
		// Could happen if the registry is a view from SSD
		return null;
	}

	private void populate_legacy(int p1, byte[] data, Kind type, GPSpec spec) throws GPDataException {
		int offset = 0;
		try {
			while (offset < data.length) {
				int len = data[offset++];
				AID aid = new AID(data, offset, len);
				offset += len;
				int lifecycle = (data[offset++] & 0xFF);
				byte privileges = data[offset++];

				if (type == Kind.IssuerSecurityDomain || type == Kind.Application) {
					GPRegistryEntryApp app = new GPRegistryEntryApp();
					app.setType(type);
					app.setAID(aid);
					app.setPrivileges(Privileges.fromByte(privileges));
					app.setLifeCycle(lifecycle);
					add(app);
				} else if (type == Kind.ExecutableLoadFile) {
					if (privileges != 0x00) {
						throw new GPDataException("Privileges of Load File is not 0x00");
					}
					GPRegistryEntryPkg pkg = new GPRegistryEntryPkg();
					pkg.setAID(aid);
					pkg.setLifeCycle(lifecycle);
					pkg.setType(type);
					// Modules TODO: remove
					if (spec != GPSpec.OP201 && p1 != 0x20) {
						int num = data[offset++];
						for (int i = 0; i < num; i++) {
							len = data[offset++] & 0xFF;
							aid = new AID(data, offset, len);
							offset += len;
							pkg.addModule(aid);
						}
					}
					add(pkg);
				}
			}
		}
		catch (ArrayIndexOutOfBoundsException e) {
			throw new GPDataException("Invalid response to GET STATUS", e);
		}
	}

	private void populate_tags(byte[] data, Kind type) throws GPDataException {
		try (ASN1InputStream ais = new ASN1InputStream(data)) {
			while (ais.available() > 0) {
				DERApplicationSpecific registry_data = (DERApplicationSpecific) ais.readObject();
				// System.out.println(ASN1Dump.dumpAsString(registry_data, true));
				if (registry_data.getApplicationTag() == 3) {
					// XXX: a bit ugly and wasting code, we populate both objects but add only one
					GPRegistryEntryApp app = new GPRegistryEntryApp();
					GPRegistryEntryPkg pkg = new GPRegistryEntryPkg();
					ASN1Sequence seq = (ASN1Sequence) registry_data.getObject(BERTags.SEQUENCE);
					for (ASN1Encodable p: Lists.newArrayList(seq.iterator())) {
						if (p instanceof DERApplicationSpecific) {
							ASN1ApplicationSpecific entry = DERApplicationSpecific.getInstance(p);
							if (entry.getApplicationTag() == 15) {
								AID aid = new AID(entry.getContents());
								app.setAID(aid);
								pkg.setAID(aid);
							} else if (entry.getApplicationTag() == 5) {
								// privileges
								Privileges privs = Privileges.fromBytes(entry.getContents());
								app.setPrivileges(privs);
							} else if (entry.getApplicationTag() == 4) {
								AID a = new AID(entry.getContents());
								app.setLoadFile(a);
							} else if (entry.getApplicationTag() == 12) {
								AID a = new AID(entry.getContents());
								app.setDomain(a);
								pkg.setDomain(a);
							} else if (entry.getApplicationTag() == 14) {
								pkg.setVersion(entry.getContents());
							} else {
								// XXX there are cards that have unknown tags.
								// Normally we'd like to avoid having proprietary data
								// but the rest of the response parses OK. So just ignore these
								// tags instead of throwing an exception
								logger.warn("Unknown tag: " + HexUtils.bin2hex(entry.getEncoded()));
							}
						} else if (p instanceof DERTaggedObject) {
							ASN1TaggedObject tag = DERTaggedObject.getInstance(p);
							if (tag.getTagNo() == 112) { // lifecycle
								ASN1OctetString lc = DEROctetString.getInstance(tag, false);
								app.setLifeCycle(lc.getOctets()[0] & 0xFF);
								pkg.setLifeCycle(lc.getOctets()[0] & 0xFF);
							} else if (tag.getTagNo() == 4) { // Executable module AID
								ASN1OctetString lc = DEROctetString.getInstance(tag, false);
								AID a = new AID(lc.getOctets());
								pkg.addModule(a);
							} else {
								logger.warn("Unknown data: " + HexUtils.bin2hex(tag.getEncoded()));
							}
						}
					}
					// Construct entry
					if (type == Kind.ExecutableLoadFile) {
						pkg.setType(type);
						add(pkg);
					} else {
						app.setType(type);
						add(app);
					}
				} else {
					throw new GPDataException("Invalid tag", registry_data.getEncoded());
				}
			}
		} catch (IOException e) {
			throw new GPDataException("Invalid data", e);
		}
	}

	// FIXME: this is ugly
	public void parse(int p1, byte[] data, Kind type, GPSpec spec) throws GPDataException {
		if (tags) {
			populate_tags(data, type);
		} else {
			populate_legacy(p1, data, type, spec);
		}
	}
}
