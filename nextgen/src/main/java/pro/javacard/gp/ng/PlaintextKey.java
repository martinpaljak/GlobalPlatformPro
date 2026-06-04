// SPDX-FileCopyrightText: 2021 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Optional;

// Helper to convert command line parameters to meaningful key objects.
public final class PlaintextKey {
    private final Key symmetricKey;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final String s;

    private PlaintextKey(final String s, final Key sym, final PublicKey publicKey, final PrivateKey privateKey) {
        this.symmetricKey = sym;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.s = s;
    }

    public Optional<Key> getSymmetric() {
        return Optional.ofNullable(symmetricKey);
    }

    public Optional<PublicKey> getPublic() {
        return Optional.ofNullable(publicKey);
    }

    public Optional<PrivateKey> getPrivate() {
        return Optional.ofNullable(privateKey);
    }
    
    // A value that isn't a parseable path on this OS (e.g. "aes:..." on Windows,
    // where ':' is invalid in a path element) is simply not a file.
    private static Optional<Path> asReadableFile(final String v) {
        try {
            final Path p = Paths.get(v);
            return Files.isReadable(p) ? Optional.of(p) : Optional.empty();
        } catch (InvalidPathException e) {
            return Optional.empty();
        }
    }

    public static PlaintextKey valueOf(final String v) {
        final var file = asReadableFile(v);
        if (file.isPresent()) {
            final var p = file.get();
            try (InputStream inputStream = Files.newInputStream(p)) {
                try (var pem = new PEMParser(new InputStreamReader(inputStream, StandardCharsets.US_ASCII))) {
                    final var ohh = pem.readObject();
                    if (ohh instanceof PEMKeyPair kp) {
                        final var keyPair = new JcaPEMKeyConverter().getKeyPair(kp);
                        return new PlaintextKey(v, null, keyPair.getPublic(), keyPair.getPrivate());
                    } else if (ohh instanceof SubjectPublicKeyInfo spki) {
                        return new PlaintextKey(v, null, new JcaPEMKeyConverter().getPublicKey(spki), null);
                    } else if (ohh instanceof X509CertificateHolder certHolder) {
                        try {
                            return new PlaintextKey(v, null, new JcaX509CertificateConverter().getCertificate(certHolder).getPublicKey(), null);
                        } catch (CertificateException ce) {
                            throw new IllegalArgumentException("Can not read certificate from PEM: " + ce.getMessage());
                        }
                    } else if (ohh instanceof PrivateKeyInfo pki) {
                        final var pk = new JcaPEMKeyConverter().getPrivateKey(pki);
                        if (pk instanceof RSAPrivateKey rsaKey) {
                            final var modulus = rsaKey.getModulus();
                            final var exponent = rsaKey.getPublicExponent();
                            final var publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
                            return new PlaintextKey(v, null, publicKey, pk);
                        } else if (pk instanceof RSAPrivateCrtKey rsaCrtKey) {
                            final var modulus = rsaCrtKey.getModulus();
                            final var exponent = rsaCrtKey.getPublicExponent();
                            final var publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
                            return new PlaintextKey(v, null, publicKey, pk);
                        } else {
                            return new PlaintextKey(v, null, null, pk);
                        }
                    } else {
                        throw new IllegalArgumentException("Can not read PEM");
                    }
                }
            } catch (IOException | GeneralSecurityException e) {
                throw new IllegalArgumentException("Could not read PEM: " + e.getMessage(), e);
            }
        } else {
            if (v.startsWith("aes:")) {
                final byte[] bv = HexUtils.hex2bin(v.substring(4));
                if (bv.length == 16 || bv.length == 24 || bv.length == 32) {
                    return new PlaintextKey(v, GPCrypto.aeskey(bv), null, null);
                } else {
                    throw new IllegalArgumentException("Invalid key length: " + bv.length);
                }
            } else if (v.startsWith("3des:")) {
                final byte[] bv = HexUtils.hex2bin(v.substring(5));
                if (bv.length == 16) {
                    return new PlaintextKey(v, GPCrypto.des3key(bv), null, null);
                } else {
                    throw new IllegalArgumentException("Invalid key length: " + bv.length);
                }
            } else {
                final byte[] k = HexUtils.hex2bin(v);
                if (k.length == 24 || k.length == 32) {
                    return new PlaintextKey(v, GPCrypto.aeskey(k), null, null);
                } else if (k.length == 16) {
                    return new PlaintextKey(v, GPCrypto.des3key(k), null, null);
                } else {
                    throw new IllegalArgumentException("Invalid key length: " + k.length);
                }
            }
        }
    }

    @Override
    public String toString() {
        return s;
    }
}
