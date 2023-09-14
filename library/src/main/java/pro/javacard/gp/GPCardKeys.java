/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-present Martin Paljak, martin@martinpaljak.net
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

import apdu4j.core.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;


// Provides a interface for session keys. Session keys are derived from card keys
// Session keys are PLAINTEXT keys.
// Providers are free to derive session keys based on hardware backed master keys
// PlaintextKeys provides card keys, that are ... plaintext (not backed by hardware)
public abstract class GPCardKeys {
    public GPCardKeys() {}
    private static final Logger logger = LoggerFactory.getLogger(GPCardKeys.class);

    // Key diversification support.
    protected GPSecureChannelVersion.SCP scp; // The actual SCP version, to know how to handle DEK
    protected byte[] kdd; // The key derivation data that was used to get the keys in question. May be empty (no derivation)
    private boolean diversified = false;

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

    // Encrypt data with card DEK (session DEK in case of SCP02)
    public abstract byte[] encrypt(byte[] data, byte[] sessionContext) throws GeneralSecurityException;

    // Encrypt another key with card DEK (session DEK in case of SCP02)
    public abstract byte[] encryptKey(GPCardKeys key, KeyPurpose p, byte[] sessionContext) throws GeneralSecurityException;

    // Get session keys for given session data
    public abstract byte[] getSessionKey(KeyPurpose keyPurpose, byte[] sessionContext);

    // Get KCV of a card key
    public abstract byte[] kcv(KeyPurpose p);

    // Diversify card keys automatically, based on INITIALIZE UPDATE response
    public GPCardKeys diversify(GPSecureChannelVersion.SCP scp, byte[] kdd) {
        if (diversified)
            throw new IllegalStateException("Keys already diversified!");
        this.scp = scp; // We know for sure what is the type of the key.
        if (this.kdd != null && !Arrays.equals(this.kdd, kdd)) {
            logger.warn("KDD-s don't match: {} vs {}", HexUtils.bin2hex(this.kdd), HexUtils.bin2hex(kdd));
        }
        this.kdd = kdd.clone();
        diversified = true;
        return this;
    }

    // Return key derivation data for this keyset
    public Optional<byte[]> getKDD() {
        return Optional.ofNullable(kdd == null ? null : kdd.clone());
    }

    @Override
    public String toString() {
        return String.format("KCV-s (%s) ENC=%s MAC=%s DEK=%s", scp, HexUtils.bin2hex(kcv(KeyPurpose.ENC)), HexUtils.bin2hex(kcv(KeyPurpose.MAC)), HexUtils.bin2hex(kcv(KeyPurpose.DEK)));
    }
}
