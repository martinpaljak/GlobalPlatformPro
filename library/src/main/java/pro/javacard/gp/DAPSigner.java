// SPDX-FileCopyrightText: 2022 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.capfile.CAPFile;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

public final class DAPSigner {

    private static final Logger log = LoggerFactory.getLogger(DAPSigner.class);

    private DAPSigner() {}

    public static byte[] sign(final CAPFile cap, final PrivateKey key, final GPData.LFDBH hash) throws GeneralSecurityException {
        final var dtbs = cap.getLoadFileDataHash(hash.algo);
        if (key instanceof RSAPrivateKey rkey) {
            log.info("Signing DAP with {}-bit RSA and {}", rkey.getModulus().bitLength(), hash);
            return GPCrypto.rsa_sign(rkey, dtbs);
        } else if (key instanceof ECPrivateKey ecKey) {
            // B.4.3 ECDSA of GPC 2.3.1
            final var bitLength = ecKey.getParams().getOrder().bitLength();
            final var componentLength = (bitLength + 7) / 8;
            String sigAlgo;
            if(bitLength < 256) {
                throw new IllegalArgumentException("Unsupported ECDSA DAP key length");
            } else if (bitLength < 384) {
                sigAlgo = "SHA256withECDSA";
            } else if (bitLength < 512) {
                sigAlgo = "SHA384withECDSA";
            } else {
                sigAlgo = "SHA512withECDSA";
            }
            log.info("Signing DAP with EC key, component length {} using {}", componentLength, sigAlgo);
            final Signature signer = Signature.getInstance(sigAlgo);
            signer.initSign(key);
            signer.update(dtbs);
            return GPCrypto.der2rs(signer.sign(), componentLength);
        }
        throw new IllegalArgumentException("Unsupported DAP key: " + key.getAlgorithm());
    }

    public static byte[] mac(final CAPFile cap, final Key key, final GPData.LFDBH hash) {
        final var dtbs = cap.getLoadFileDataHash(hash.algo);
        if(key.getAlgorithm().equals("AES")) {
            log.info("Signing DAP with {}-bit AES CMAC and {}", key.getEncoded().length * 8, hash);
            return GPCrypto.aes_cmac(key.getEncoded(), dtbs, 128);
        } else if(key.getAlgorithm().equals("DESede")) {
            throw new IllegalArgumentException("3DES DAP keys are not supported yet");
        } else {
            throw new IllegalArgumentException("Unsupported DAP key: " + key.getAlgorithm());
        }
    }
}
