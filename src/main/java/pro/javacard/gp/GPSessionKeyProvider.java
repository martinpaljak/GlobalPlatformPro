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

// Provides a interface for session keys. Session keys are derived from card keys
// Session keys are PLAINTEXT keys.
// Providers are free to derive session keys based on hardware backed master keys
// PlaintextKeys provides card keys, that are ... plaintext (not backed by hardware)

public abstract class GPSessionKeyProvider {

    // returns true if keys can probably be made
    public abstract boolean init(byte[] atr, byte[] cplc, byte[] kinfo);

    // Any can be null, if N/A for SCP version
    public abstract void calculate(int scp, byte[] kdd, byte[] host_challenge, byte[] card_challenge, byte[] ssc) throws GPException;

    public abstract GPKey getKeyFor(KeyPurpose p);

    public abstract int getID();

    public abstract int getVersion();

    // Session keys are used for various purposes
    public enum KeyPurpose {
        // ID is as used in diversification/derivation
        // That is - one based.
        ENC(1), MAC(2), DEK(3), RMAC(4);

        private final int value;

        KeyPurpose(int value) {
            this.value = value;
        }

        public byte getValue() {
            return (byte) (value & 0xFF);
        }
    }

}
