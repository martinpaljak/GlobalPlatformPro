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

public enum GPSecureChannel {
    SCP01(1), SCP02(2), SCP03(3);

    private final int value;
    private int i = 0;

    GPSecureChannel(int value) {
        this.value = value;
    }

    public byte getValue() {
        return (byte) (value & 0xFF);
    }

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("ME_ENUM_FIELD_SETTER")
    public void setI(int i) {
        this.i = i;
    }

    public int getI() {
        return i;
    }

    public static Optional<GPSecureChannel> valueOf(int i) {
        for (GPSecureChannel v : values())
            if (v.value == i)
                return Optional.of(v);
        return Optional.empty();
    }

    public String toString() {
        return i == 0 ? name() : String.format("%s (i=%02x)", name(), i);
    }
}
