/*
 * Copyright (c) 2018 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package pro.javacard.capfile;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

public class CAPFileSigner {
    static final ECParameterSpec secp256r1;

    static {
        try {
            // Stupid, but ... There is no other sane way to get parameters than copying from a key
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair tmp = generator.generateKeyPair();
            secp256r1 = ((ECPublicKey) tmp.getPublic()).getParams();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Can not generate key for parameter extraction!");
        }
    }

    private CAPFileSigner() {}
    // Variant 1
    public static void addSignature(CAPFile cap, PrivateKey key) throws GeneralSecurityException {
        if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rkey = (RSAPrivateKey) key;
            if ((rkey.getModulus().bitLength() + 7) / 8 == 128) {
                Signature signer = Signature.getInstance("SHA1withRSA");
                signer.initSign(key);
                signer.update(cap.getLoadFileDataHash("SHA1"));
                byte[] dap = signer.sign();
                cap.entries.put("META-INF/" + CAPFile.DAP_RSA_V1_SHA1_FILE, dap);
                signer.initSign(key);
                signer.update(cap.getLoadFileDataHash("SHA-256"));
                dap = signer.sign();
                cap.entries.put("META-INF/" + CAPFile.DAP_RSA_V1_SHA256_FILE, dap);
                return;
            }
        } else if (key instanceof ECPrivateKey) {
            ECPrivateKey ekey = (ECPrivateKey) key;
            if (ekey.getParams().equals(secp256r1)) {
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(key);
                signer.update(cap.getLoadFileDataHash("SHA-1"));
                byte[] dap = signer.sign();
                cap.entries.put("META-INF/" + CAPFile.DAP_P256_SHA1_FILE, dap);
                signer.initSign(key);
                signer.update(cap.getLoadFileDataHash("SHA-256"));
                dap = signer.sign();
                cap.entries.put("META-INF/" + CAPFile.DAP_P256_SHA256_FILE, dap);
                return;
            }
        }
        throw new IllegalArgumentException("Only 1024 bit RSA and P256 EC keys are supported!");
    }

    public static PrivateKey pem2privatekey(String f) throws IOException {
        // This pleases both spotbugs and lgtm.
        try (InputStream in = new FileInputStream(f); PEMParser pem = new PEMParser(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            Object ohh = pem.readObject();
            if (ohh instanceof PEMKeyPair) {
                PEMKeyPair kp = (PEMKeyPair) ohh;
                return new JcaPEMKeyConverter().getKeyPair(kp).getPrivate();
            } else if (ohh instanceof PrivateKeyInfo) {
                return new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) ohh);
            } else throw new IllegalArgumentException("Can not read PEM");
        }
    }
}
