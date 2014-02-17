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

package openkms.gp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Convenience class managing a vector of {@link AIDRegistryEntry
 * AIDRegistryEntries} with search functionality.
 *
 * Implements {@code Iterable<AIDRegistryEntry} to permit foreach loops such as
 * {@code for(AIDRegistryEntry e : registry) ...}.
 */
public class AIDRegistry implements Iterable<AIDRegistryEntry> {

	List<AIDRegistryEntry> entries = new ArrayList<AIDRegistryEntry>();

	/**
	 * Add one entry to this registry.
	 *
	 * @param entry
	 */
	public void add(AIDRegistryEntry entry) {
		entries.add(entry);
	}

	/**
	 * Returns an iterator that iterates over all entries in this registry.
	 *
	 * @return iterator
	 */
	public Iterator<AIDRegistryEntry> iterator() {
		return entries.iterator();
	}


	/**
	 * Returns a list of all packages in this registry.
	 *
	 * @return a list of all packages
	 */
	public List<AIDRegistryEntry> allPackages() {
		List<AIDRegistryEntry> res = new ArrayList<AIDRegistryEntry>();
		for (AIDRegistryEntry e : entries) {
			if (e.isPackage()) {
				res.add(e);
			}
		}
		return res;
	}

	public List<AID> allPackageAIDs() {
		List<AID> res = new ArrayList<AID>();
		for (AIDRegistryEntry e : entries) {
			if (e.isPackage()) {
				res.add(e.getAID());
			}
		}
		return res;
	}
	public List<AID> allAppletAIDs() {
		List<AID> res = new ArrayList<AID>();
		for (AIDRegistryEntry e : entries) {
			if (e.isApplet()) {
				res.add(e.getAID());
			}
		}
		return res;
	}
	public List<AID> allAIDs() {
		List<AID> res = new ArrayList<AID>();
		for (AIDRegistryEntry e : entries) {
			res.add(e.getAID());
		}
		return res;
	}
	/**
	 * Returns a list of all applets in this registry.
	 *
	 * @return a list of all applets
	 */
	public List<AIDRegistryEntry> allApplets() {
		List<AIDRegistryEntry> res = new ArrayList<AIDRegistryEntry>();
		for (AIDRegistryEntry e : entries) {
			if (e.isApplet()) {
				res.add(e);
			}
		}
		return res;
	}

	public AID getDefaultSelectedAID() {
		for (AIDRegistryEntry e : allApplets()) {
			if ((e.getPrivileges() & 0x04) != 0) {
				return e.getAID();
			}
		}
		return null;
	}

	public AID getDefaultSelectedPackageAID() {
		AID defaultAID = getDefaultSelectedAID();
		if (defaultAID != null) {
			for (AIDRegistryEntry e : allPackages()) {
				if (e.getExecutableAIDs().contains(defaultAID))
					return e.getAID();
			}
			// Did not get a hit. Loop packages and look for prefixes
			for (AIDRegistryEntry e : allPackages()) {
				if (defaultAID.toString().startsWith(e.getAID().toString()))
					return e.getAID();
			}
		}
		return null;
	}
}
