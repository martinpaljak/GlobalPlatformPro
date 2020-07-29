/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2020-present Martin Paljak, martin@martinpaljak.net
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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

// Various per-device configurations and workarounds
// TODO: WIP, overrides, interface
public abstract class GPCardProfile {

    static final Map<String, GPCardProfile> profiles;

    static {
        LinkedHashMap<String, GPCardProfile> tmp = new LinkedHashMap<>();
        tmp.put("default", defaultProfile());
        tmp.put("old", new OldCardProfile());
        profiles = Collections.unmodifiableMap(tmp);
    }

    protected boolean useTags = true;
    protected boolean reportsModules = true;
    protected boolean oldStyleSSD = false;

    public boolean getStatusUsesTags() {
        return useTags;
    }

    public boolean doesReportModules() {
        return reportsModules;
    }

    public boolean oldStyleSSDParameters() {
        return oldStyleSSD;
    }

    static class DefaultModernProfile extends GPCardProfile {

    }

    static class OldCardProfile extends GPCardProfile {
        OldCardProfile() {
            useTags = false;
            reportsModules = false;
            oldStyleSSD = true;
        }
    }

    static GPCardProfile defaultProfile() {
        return new DefaultModernProfile();
    }

    static Optional<GPCardProfile> fromCPLC(byte[] cplc) {
        return Optional.of(defaultProfile());
    }

    static Optional<GPCardProfile> fromName(String name) {
        return Optional.ofNullable(profiles.get(name));
    }
}
