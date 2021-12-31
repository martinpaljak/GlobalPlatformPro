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

import java.util.Optional;

public final class GPSecureChannelVersion {
    public final int i;
    public final SCP scp;

    public enum SCP {
        SCP01(1), SCP02(2), SCP03(3);

        private final int value;

        SCP(int value) {
            this.value = value;
        }

        public byte getValue() {
            return (byte) (value & 0xFF);
        }

        public static Optional<SCP> valueOf(int i) {
            for (SCP v : values())
                if (v.value == i)
                    return Optional.of(v);
            return Optional.empty();
        }
    }

    public GPSecureChannelVersion(SCP scp, int i) {
        this.scp = scp;
        this.i = i;
    }

    public static GPSecureChannelVersion valueOf(int v) {
        return valueOf(v, 0);
    }

    public static GPSecureChannelVersion valueOf(int v, int i) {
        SCP scp = SCP.valueOf(v).orElseThrow(() -> new IllegalArgumentException("Unknown SCP version: " + v));
        return new GPSecureChannelVersion(scp, i);
    }

    public String toString() {
        return i == 0 ? scp.name() : String.format("%s (i=%02x)", scp.name(), i);
    }
}
