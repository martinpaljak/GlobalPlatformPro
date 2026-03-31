/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2026-present Martin Paljak, martin@martinpaljak.net
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
package pro.javacard.gp.ng;

import java.util.Arrays;

// Ephemeral session keys produced by CardKeys.deriveSession().
// Each SCP variant carries exactly the bytes its SCP wrapper needs.
// Session DEK is absent - DEK operations stay inside CardKeys.
public sealed interface SessionKeys permits SessionKeys.SCP01Keys, SessionKeys.SCP02Keys, SessionKeys.SCP03Keys {

    record SCP01Keys(byte[] enc, byte[] mac) implements SessionKeys, AutoCloseable {
        @Override
        public void close() {
            Arrays.fill(enc, (byte) 0);
            Arrays.fill(mac, (byte) 0);
        }
    }

    record SCP02Keys(byte[] enc, byte[] mac, byte[] rmac) implements SessionKeys, AutoCloseable {
        @Override
        public void close() {
            Arrays.fill(enc, (byte) 0);
            Arrays.fill(mac, (byte) 0);
            Arrays.fill(rmac, (byte) 0);
        }
    }

    record SCP03Keys(byte[] enc, byte[] mac, byte[] rmac) implements SessionKeys, AutoCloseable {
        @Override
        public void close() {
            Arrays.fill(enc, (byte) 0);
            Arrays.fill(mac, (byte) 0);
            Arrays.fill(rmac, (byte) 0);
        }
    }
}
