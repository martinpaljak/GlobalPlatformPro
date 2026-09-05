// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import pro.javacard.gp.GPSecureChannelVersion.SCP;

import java.util.List;
import java.util.Optional;

// HSM-friendly key provider interface. Assumes master keys are inaccessible -
// only session keys and DEK-encrypted ciphertext come out.
// Not sealed - HSM implementations live outside this module.
public interface CardKeys {

    // Card key purposes (stored on card). RMAC excluded - it's derived from MAC at session level.
    enum KeyPurpose {
        ENC(1), MAC(2), DEK(3);

        private final int value;

        KeyPurpose(int value) {
            this.value = value;
        }

        public byte getValue() {
            return (byte) (value & 0xFF);
        }

        public static List<KeyPurpose> cardKeys() {
            return List.of(ENC, MAC, DEK);
        }
    }

    // Key metadata
    record KeyInfo(int version, int id, int length, KeyType type) {
        public enum KeyType {
            DES3, AES
        }
    }

    // Bind to a specific card. Returns a NEW instance - original unchanged.
    // For master key + KDF: derives card-specific keys from KDD.
    // For pre-diversified keys: binds SCP/KDD metadata only.
    CardKeys diversify(SCP scp, byte[] kdd);

    // Derive ephemeral session keys for APDU wrapping.
    SessionKeys deriveSession(byte[] sessionContext);

    // Encrypt padded data under DEK.
    // SCP02: internally derives session DEK from sessionContext.
    // SCP01/SCP03: uses card DEK directly.
    byte[] encryptDEK(byte[] data, byte[] sessionContext);

    // Wrap a raw key value under DEK for PUT KEY.
    // SCP03: adds random padding before AES-CBC.
    byte[] wrapKey(byte[] keyValue, byte[] sessionContext);

    // CMAC-KDF on a card key - for SCP03 pseudo-random challenge verification.
    byte[] kdf(KeyPurpose purpose, byte[] a, byte[] b, int bytes);

    // Key check value for a card key.
    byte[] kcv(KeyPurpose purpose);

    // Key metadata (version, type, length).
    KeyInfo keyInfo();

    // The SCP this key set is bound to (known after diversify).
    Optional<SCP> scp();
}
