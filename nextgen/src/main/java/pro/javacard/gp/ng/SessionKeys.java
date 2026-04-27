// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

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
