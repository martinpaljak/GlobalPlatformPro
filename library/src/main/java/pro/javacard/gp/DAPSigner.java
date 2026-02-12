package pro.javacard.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.capfile.CAPFile;

import java.security.GeneralSecurityException;
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
            log.info("Signing DAP with {} RSA and {}", rkey.getModulus().bitLength(), hash);
            return GPCrypto.rsa_sign(rkey, dtbs);
        } else if (key instanceof ECPrivateKey ecKey) {
            // B.4.3 ECDSA of GPC 2.3.1
            final var componentLength = (ecKey.getParams().getOrder().bitLength() + 7) / 8;
            final String sigAlgo = componentLength > 32 ? "SHA384withECDSA" : "SHA256withECDSA";
            log.info("Signing DAP with EC key, component length {} using {}", componentLength, sigAlgo);
            final Signature signer = Signature.getInstance(sigAlgo);
            signer.initSign(key);
            signer.update(cap.getLoadFileDataHash(hash.algo));
            return GPCrypto.der2rs(signer.sign(), componentLength);
        }
        throw new IllegalArgumentException("Unsupported DAP key: " + key.getAlgorithm());
    }
}
