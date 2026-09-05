// SPDX-FileCopyrightText: 2020 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

// Various per-device configurations and workarounds
// TODO: retire with preferences
public final class GPCardProfile {

    private static final GPCardProfile MODERN = new GPCardProfile(true, true, false);
    private static final GPCardProfile OLD = new GPCardProfile(false, false, true);

    public static final Map<String, GPCardProfile> profiles;

    static {
        final var tmp = new LinkedHashMap<String, GPCardProfile>();
        tmp.put("default", MODERN);
        tmp.put("old", OLD);
        profiles = Collections.unmodifiableMap(tmp);
    }

    private final boolean useTags;
    private final boolean reportsModules;
    private final boolean oldStyleSSD;

    private GPCardProfile(final boolean useTags, final boolean reportsModules, final boolean oldStyleSSD) {
        this.useTags = useTags;
        this.reportsModules = reportsModules;
        this.oldStyleSSD = oldStyleSSD;
    }

    public boolean getStatusUsesTags() {
        return useTags;
    }

    public boolean doesReportModules() {
        return reportsModules;
    }

    public boolean oldStyleSSDParameters() {
        return oldStyleSSD;
    }

    public static GPCardProfile defaultProfile() {
        return MODERN;
    }

    static Optional<GPCardProfile> fromCPLC(final byte[] cplc) {
        return Optional.of(defaultProfile());
    }

    public static Optional<GPCardProfile> fromName(final String name) {
        return Optional.ofNullable(profiles.get(name));
    }
}
