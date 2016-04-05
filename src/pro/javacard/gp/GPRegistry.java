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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;

/**
 * Convenience class managing a vector of {@link GPRegistryEntry
 * AIDRegistryEntries} with search functionality.
 *
 * Implements {@code Iterable<GPRegistryEntry} to permit foreach loops such as
 * {@code for(GPRegistryEntry e : registry) ...}.
 */
public class GPRegistry implements Iterable<GPRegistryEntry> {

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
}
