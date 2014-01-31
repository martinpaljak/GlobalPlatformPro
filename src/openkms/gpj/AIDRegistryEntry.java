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

package openkms.gpj;

import java.util.ArrayList;
import java.util.List;

/**
 * One entry in the card registry.
 *
 * Describes one entry of the card registry, consisting of
 * <UL>
 * <LI>application ID (as {@link AID})
 * <LI>the life cycle status (as integer)
 * <LI>the privileges (in encoded form as integer)
 * <LI>the list of ?? (as array of {@link AID AID's}
 * <LI>and the kind
 * </UL>
 *
 */
public class AIDRegistryEntry {

	/**
	 * The four different kinds of ??.
	 */
	public static enum Kind {
		IssuerSecurityDomain, Application, SecurityDomain, ExecutableLoadFiles, ExecutableLoadFilesAndModules;

		/**
		 * Convert a kind into a three letter string.
		 *
		 * @return a three letter abbreviation
		 */
		public String toShortString() {
			switch (this) {
			case IssuerSecurityDomain:
				return "ISD";
			case Application:
				return "App";
			case SecurityDomain:
				return "SeD";
			case ExecutableLoadFiles:
				return "Exe";
			case ExecutableLoadFilesAndModules:
				return "ExM";
			}
			return "???";
		}
	}

	private final AID aid;

	private final int lifeCycleState;

	private final int privileges;

	private final List<AID> executableAIDS;

	private final Kind kind;

	/**
	 * Create a new entry.
	 *
	 * @param aid
	 *            the application ID
	 * @param lifeCycleState
	 * @param privileges
	 *            encoded as int
	 * @param kind
	 */
	public AIDRegistryEntry(AID aid, int lifeCycleState, int privileges, Kind kind) {
		this.aid = aid;
		this.lifeCycleState = lifeCycleState & 0xff;
		this.privileges = privileges & 0xff;
		this.kind = kind;
		executableAIDS = new ArrayList<AID>();
	}

	/**
	 * Add an executable application ID to this entry.
	 *
	 * @param aid
	 *            application ID
	 */
	public void addExecutableAID(AID aid) {
		executableAIDS.add(aid);
	}

	/**
	 * Return the application ID of this entry.
	 *
	 * @return application ID
	 */
	public AID getAID() {
		return aid;
	}

	/**
	 * Return the life cycle state of this entry.
	 *
	 * @return live cycle state
	 */
	public int getLifeCycleState() {
		return lifeCycleState;
	}

	/**
	 * Return the priveledges of this entry.
	 *
	 * @return priveledges, encoded into an int
	 */
	public int getPrivileges() {
		return privileges;
	}

	/**
	 * Return the kind of this entry.
	 *
	 * @return kind
	 */
	public Kind getKind() {
		return kind;
	}

	/**
	 * Return true if this entry describes a package.
	 *
	 * @return true if this entry is a package
	 */
	public boolean isPackage() {
		return (kind == Kind.ExecutableLoadFilesAndModules) || (kind == Kind.ExecutableLoadFiles);
	}

	/**
	 * Return true if this entry describes an applet.
	 *
	 * @return true if this entry is an applet
	 */
	public boolean isApplet() {
		return kind == Kind.Application;
	}

	/**
	 * Return all executable application ID's of this entry.
	 *
	 * @return application ID's
	 */
	public List<AID> getExecutableAIDs() {
		List<AID> result = new ArrayList<AID>();
		result.addAll(executableAIDS);
		return result;
	}

	/**
	 * Return a string representation of this entry.
	 *
	 * @return description
	 */
	public String toString() {
		StringBuffer result = new StringBuffer();
		result.append("AID: " + aid + ", " + lifeCycleState + ", " + privileges + ", Kind: " + kind.toShortString());

		for (AID a : executableAIDS) {
			result.append("\n  " + a);
		}
		return result.toString();
	}

	public String getLifeCycleString() {
		switch (kind) {
		case IssuerSecurityDomain:
			switch (lifeCycleState) {
			case 0x1:
				return "OP_READY";
			case 0x7:
				return "INITIALIZED";
			case 0xF:
				return "SECURED";
			case 0x7F:
				return "CARD_LOCKED";
			case 0xFF:
				return "TERMINATED";
			default:
				return "ERROR";
			}
		case Application:
			if (lifeCycleState == 0x3) {
				return "INSTALLED";
			} else if (lifeCycleState <= 0x7F) {
				return "SELECTABLE";
			} else if (lifeCycleState > 0x83) {
				return "LOCKED";
			} else {
				return "ERROR";
			}
		case ExecutableLoadFilesAndModules:
			if (lifeCycleState == 0x1) {
				return "LOADED";
			} else if (lifeCycleState == 0x00) {
				// OP201
				return "LOGICALLY_DELETED";
			} else {
				return "ERROR";
			}
		case ExecutableLoadFiles:
			if (lifeCycleState == 0x1) {
				return "LOADED";
			} else if (lifeCycleState == 0x00) {
				// OP201
				return "LOGICALLY_DELETED";
			} else {
				return "ERROR";
			}
		default:
			return "ERROR";
		}
	}

	public String getPrivilegesString() {
		ArrayList<String> privs = new ArrayList<String>();

		int r = privileges;

		if (r == 0) {
			privs.add("(none)");
		} else {
			if ((r & (1<<7)) != 0) {
				r &= ~(1<<7);
				privs.add("Security Domain");
			}
			if ((r & (1<<4)) != 0) {
				r &= ~(1<<4);
				privs.add("Card lock");
			}
			if ((r & (1<<3)) != 0) {
				r &= ~(1<<3);
				privs.add("Card terminate");
			}
			if ((r & (1<<2)) != 0) {
				r &= ~(1<<2);
				privs.add("Default selected");
			}
			if ((r & (1<<1)) != 0) {
				r &= ~(1<<1);
				privs.add("CVM (PIN) management");
			}
		}
		StringBuffer result = new StringBuffer();
		// http://findbugs.sourceforge.net/bugDescriptions.html#SBSC_USE_STRINGBUFFER_CONCATENATION

		for (int i = 0; i < privs.size(); i++) {
			if (i != 0) {
				result.append(", ");
			}
			result.append(privs.get(i));
		}

		// TODO: Wait until actual cards discovered
		if (r>0) {
			result.append(" " + Integer.toHexString(r));
		}
		return result.toString().trim();
	}
}
