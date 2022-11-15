package pro.javacard.gp;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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

    public static byte[] sign(CAPFile cap, PrivateKey key, GPData.LFDBH hash) throws GeneralSecurityException {
        if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rkey = (RSAPrivateKey) key;
            if ((rkey.getModulus().bitLength() + 7) / 8 == 128) {
                // B.3.1 Scheme1 of RSA keys up to 1k
                if (!Arrays.asList(GPData.LFDBH.SHA1, GPData.LFDBH.SHA256).contains(hash))
                    throw new IllegalArgumentException("Unsupported hash for DAP: " + hash);
                final Signature signer = Signature.getInstance(String.format("%swithRSA", hash.algo.replace("-", "")));
                signer.initSign(key);
                signer.update(cap.getLoadFileDataHash(hash.algo));
                byte[] dap = signer.sign();
                return dap;
            } else {
                // B.3.2 Scheme2 of RSA keys above 1k
                MGF1ParameterSpec mgf = MGF1ParameterSpec.SHA256;
                PSSParameterSpec spec = new PSSParameterSpec(mgf.getDigestAlgorithm(), "MGF1", mgf, 32, PSSParameterSpec.TRAILER_FIELD_BC);
                Signature signer = Signature.getInstance("SHA256withRSAandMGF1");
                signer.setParameter(spec);
                signer.initSign(key);
                signer.update(cap.getLoadFileDataHash(hash.algo));
                byte[] dap = signer.sign();
                return dap;
            }
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
