package pro.javacard.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.capfile.CAPFile;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;

public class DAPSigner {

    private static final Logger log = LoggerFactory.getLogger(DAPSigner.class);

    private DAPSigner() {
    }

    public static byte[] sign(CAPFile cap, PrivateKey key, GPData.LFDBH hash) throws GeneralSecurityException {
        byte[] dtbs = cap.getLoadFileDataHash(hash.algo);
        if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rkey = (RSAPrivateKey) key;
            log.info("Signing DAP with {} RSA and {}", rkey.getModulus().bitLength(), hash);
            return GPCrypto.rsa_sign(rkey, dtbs);
        } else if (key instanceof ECPrivateKey) {
            // B.4.3 ECDSA of GPC 2.3.1
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(key);
            signer.update(cap.getLoadFileDataHash(hash.algo));
            byte[] dap = GPCrypto.der2rs(signer.sign(), 32); // FIXME: detect curve
            return dap;
        }
        throw new IllegalArgumentException("Unsupported DAP key: " + key.getAlgorithm());
    }
}
