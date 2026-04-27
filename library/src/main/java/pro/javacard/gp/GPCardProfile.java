// SPDX-FileCopyrightText: 2020 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

// Various per-device configurations and workarounds
// TODO: retire with preferences
@SuppressWarnings("ClassInitializationDeadlock") // Subclasses are package-private and never loaded independently
public abstract class GPCardProfile {

    private GPCardProfile() {}

    public static final Map<String, GPCardProfile> profiles;

    static {
        final var tmp = new LinkedHashMap<String, GPCardProfile>();
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

    public static GPCardProfile defaultProfile() {
        return new DefaultModernProfile();
    }

    static Optional<GPCardProfile> fromCPLC(final byte[] cplc) {
        return Optional.of(defaultProfile());
    }

    public static Optional<GPCardProfile> fromName(final String name) {
        return Optional.ofNullable(profiles.get(name));
    }
}
