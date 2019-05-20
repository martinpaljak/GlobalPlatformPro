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

import apdu4j.HexUtils;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

public abstract class GPCardKeys {

    protected GPSecureChannel scp;
    protected byte[] kdd;

    public abstract GPKeyInfo getKeyInfo();

    // Keys are used for various purposes
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

        // RMAC is derived, but not loaded to the card
        public static List<KeyPurpose> cardKeys() {
            return Arrays.asList(ENC, MAC, DEK);
        }
    }

    // Encrypt data with static card DEK
    public abstract byte[] encrypt(byte[] data) throws GeneralSecurityException;

    // Encrypt a key with card (or session) DEK
    public abstract byte[] encryptKey(GPCardKeys key, KeyPurpose p) throws GeneralSecurityException;

    // Get session keys for given session data
    public abstract GPSessionKeys getSessionKeys(byte[] kdd);

    // Get KCV of a card key
    public abstract byte[] kcv(KeyPurpose p);

    // Diversify card keys automatically, based on INITIALIZE UPDATE response
    public GPCardKeys diversify(GPSecureChannel scp, byte[] kdd) {
        this.scp = scp;
        this.kdd = kdd.clone();
        return this;
    }

    // Return key derivation data for this keyset
    public byte[] getKDD() {
        return kdd;
    }

    @Override
    public String toString() {
        return String.format("KCV-s ENC=%s MAC=%s DEK=%s for %s", HexUtils.bin2hex(kcv(KeyPurpose.ENC)), HexUtils.bin2hex(kcv(KeyPurpose.MAC)), HexUtils.bin2hex(kcv(KeyPurpose.DEK)), scp);
    }
}
