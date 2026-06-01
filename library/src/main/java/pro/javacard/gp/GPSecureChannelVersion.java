// SPDX-FileCopyrightText: 2020 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import java.util.Optional;

public final class GPSecureChannelVersion {
    public final int i;
    public final SCP scp;

    public enum SCP {
        SCP01(0x01), SCP02(0x02), SCP03(0x03), SCP11(0x11), SCP80(0x80), SCP81(0x81);

        private final int value;

        SCP(final int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static Optional<SCP> valueOf(final int i) {
            for (SCP v : values()) {
                if (v.value == i) {
                    return Optional.of(v);
                }
            }
            return Optional.empty();
        }
    }

    public GPSecureChannelVersion(final SCP scp, final int i) {
        this.scp = scp;
        this.i = i;
    }

    public static GPSecureChannelVersion valueOf(final int v) {
        return valueOf(v, 0);
    }

    public static GPSecureChannelVersion valueOf(final int v, final int i) {
        final var scp = SCP.valueOf(v).orElseThrow(() -> new IllegalArgumentException("Unknown SCP version: " + v));
        return new GPSecureChannelVersion(scp, i);
    }

    @Override
    public String toString() {
        return i == 0 ? scp.name() : "%s (i=%02x)".formatted(scp.name(), i);
    }
}
