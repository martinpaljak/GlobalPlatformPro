/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2021-present Martin Paljak, martin@martinpaljak.net
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
package pro.javacard.gptool;

import apdu4j.core.HexUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import pro.javacard.gp.GPCrypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Optional;

// Helper to convert command line parameters to meaningful key objects.
// XXX: unfortunate name and unfortunate implementation.
public class Key {
    java.security.Key symmetricKey;
    PublicKey publicKey;
    PrivateKey privateKey;

    String s;

    private Key(String s, java.security.Key sym, PublicKey publicKey, PrivateKey privateKey) {
        this.symmetricKey = sym;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.s = s;
    }

    public Optional<java.security.Key> getSymmetric() {
        return Optional.ofNullable(symmetricKey);
    }

    public Optional<PublicKey> getPublic() {
        return Optional.ofNullable(publicKey);
    }

    public Optional<PrivateKey> getPrivate() {
        return Optional.ofNullable(privateKey);
    }

    public static Key valueOf(String v) {
        Path p = Paths.get(v);
        if (Files.isReadable(p)) {
            try (InputStream inputStream = Files.newInputStream(p)) {
                try (PEMParser pem = new PEMParser(new InputStreamReader(inputStream, StandardCharsets.US_ASCII))) {
                    Object ohh = pem.readObject();
                    if (ohh instanceof PEMKeyPair) {
                        PEMKeyPair kp = (PEMKeyPair) ohh;
                        KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair(kp);
                        return new Key(v, null, keyPair.getPublic(), keyPair.getPrivate());
                    } else if (ohh instanceof SubjectPublicKeyInfo) {
                        return new Key(v, null, new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) ohh), null);
                    } else if (ohh instanceof X509CertificateHolder) {
                        X509CertificateHolder certHolder = (X509CertificateHolder) ohh;
                        try {
                            return new Key(v, null, new JcaX509CertificateConverter().getCertificate(certHolder).getPublicKey(), null);
                        } catch (CertificateException ce) {
                            throw new IllegalArgumentException("Can not read certificate from PEM: " + ce.getMessage());
                        }
                    } else if (ohh instanceof PrivateKeyInfo) {
                        PrivateKey pk = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) ohh);
                        // TODO: do this for other key types as well
                        if (pk instanceof RSAPrivateKey) {
                            BigInteger modulus = ((RSAPrivateKey) pk).getModulus();
                            BigInteger exponent = ((RSAPrivateKey) pk).getPublicExponent();
                            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
                            return new Key(v, null, publicKey, pk);
                        } else if (pk instanceof RSAPrivateCrtKey) {
                            BigInteger modulus = ((RSAPrivateCrtKey) pk).getModulus();
                            BigInteger exponent = ((RSAPrivateCrtKey) pk).getPublicExponent();
                            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
                            return new Key(v, null, publicKey, pk);
                        } else {
                            return new Key(v, null, null, pk);
                        }
                    } else throw new IllegalArgumentException("Can not read PEM");
                }
            } catch (IOException | GeneralSecurityException e) {
                throw new IllegalArgumentException("Could not read PEM: " + e.getMessage(), e);
            }
        } else {
            if (v.startsWith("aes:")) {
                byte[] bv = HexUtils.hex2bin(v.substring(4));
                if (bv.length == 16 || bv.length == 24 || bv.length == 32) {
                    return new Key(v, GPCrypto.aeskey(bv), null, null);
                } else throw new IllegalArgumentException("Invalid key length: " + bv.length);

            } else if (v.startsWith("3des:")) {
                byte[] bv = HexUtils.hex2bin(v.substring(5));
                if (bv.length == 16) {
                    return new Key(v, GPCrypto.des3key(bv), null, null);
                } else throw new IllegalArgumentException("Invalid key length: " + bv.length);
            } else {
                byte[] k = HexUtils.hex2bin(v);
                if (k.length == 24 || k.length == 32) {
                    return new Key(v, GPCrypto.aeskey(k), null, null);
                } else if (k.length == 16) {
                    return new Key(v, GPCrypto.des3key(k), null, null);

                } else throw new IllegalArgumentException("Invalid key length: " + k.length);
            }
            // TODO: public keys as curve points.
        }
    }

    @Override
    public String toString() {
        return s;
    }
}