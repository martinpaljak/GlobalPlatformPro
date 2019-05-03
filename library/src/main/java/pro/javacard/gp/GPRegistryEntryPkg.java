/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2017 Martin Paljak, martin@martinpaljak.net
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

import apdu4j.HexUtils;
import pro.javacard.AID;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class GPRegistryEntryPkg extends GPRegistryEntry {

    private byte[] version;
    private List<AID> modules = new ArrayList<AID>();

    public byte[] getVersion() {
        if (version == null)
            return null;
        return Arrays.copyOf(version, version.length);
    }

    void setVersion(byte[] v) {
        version = Arrays.copyOf(v, v.length);
    }

    public String getVersionString() {
        if (version == null) {
            return "<null>";
        }
        if (version.length == 2) {
            return version[0] + "." + version[1];
        }
        return "<unknown format " + HexUtils.bin2hex(version) + ">";
    }

    public void addModule(AID aid) {
        modules.add(aid);
    }

    public List<AID> getModules() {
        List<AID> r = new ArrayList<AID>();
        r.addAll(modules);
        return r;
    }
}
