/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2016 Martin Paljak, martin@martinpaljak.net
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

public class GPRegistryEntryApp extends GPRegistryEntry {
	private Privileges privileges;
	private AID loadfile;

	void setPrivileges(Privileges privs)  {
		privileges = privs;
	}

	public Privileges getPrivileges() {
		return privileges;
	}

	public void setLoadFile(AID aid) {
		this.loadfile = aid;
	}

	public AID getLoadFile() {
		return loadfile;
	}
}
