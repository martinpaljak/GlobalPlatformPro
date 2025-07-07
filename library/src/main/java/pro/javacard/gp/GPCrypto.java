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

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;

// Various cryptographic primitives used for secure channel or plaintext keys
@SuppressWarnings("lgtm[java/weak-cryptographic-algorithm]")
public final class GPCrypto {
    private GPCrypto() {
    }

    private static final byte[] one_bytes_16 = new byte[]{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    // List of used ciphers.
    public static final String DES3_CBC_CIPHER = "DESede/CBC/NoPadding";
    public static final String DES3_ECB_CIPHER = "DESede/ECB/NoPadding";
    static final String DES_CBC_CIPHER = "DES/CBC/NoPadding";
    static final String DES_ECB_CIPHER = "DES/ECB/NoPadding";
    static final String AES_CBC_CIPHER = "AES/CBC/NoPadding";

    // Shared random
    private static final SecureRandom rnd;

    static {
        try {
            rnd = SecureRandom.getInstance("SHA1PRNG");
            rnd.nextBytes(new byte[2]); // Force seeding
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Need SecureRandom to run");
        }
    }

    public static byte[] random(int num) {
        byte[] bytes = new byte[num];
        rnd.nextBytes(bytes);
        return bytes;
    }

    public static byte[] pad80(byte[] text, int blocksize) {
        int total = (text.length / blocksize + 1) * blocksize;
        byte[] result = Arrays.copyOfRange(text, 0, total);
        result[text.length] = (byte) 0x80;
        return result;
    }

    public static byte[] unpad80(byte[] text) throws BadPaddingException {
        if (text.length < 1)
            throw new BadPaddingException("Invalid ISO 7816-4 padding");
        int offset = text.length - 1;
        while (offset > 0 && text[offset] == 0) {
            offset--;
        }
        if (text[offset] != (byte) 0x80) {
            throw new BadPaddingException("Invalid ISO 7816-4 padding");
        }
        return Arrays.copyOf(text, offset);
    }

    private static void buffer_increment(byte[] buffer, int offset, int len) {
        if (len < 1)
            return;
        for (int i = offset + len - 1; i >= offset; i--) {
            if (buffer[i] != (byte) 0xFF) {
                buffer[i]++;
                break;
            } else
                buffer[i] = (byte) 0x00;
        }
    }

    public static void buffer_increment(byte[] buffer) {
        buffer_increment(buffer, 0, buffer.length);
    }

    public static byte[] aes_cbc(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(AES_CBC_CIPHER);
        c.init(Cipher.ENCRYPT_MODE, aeskey(key), new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    public static byte[] aes_cbc_decrypt(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(AES_CBC_CIPHER);
        c.init(Cipher.DECRYPT_MODE, aeskey(key), new IvParameterSpec(iv));
        return c.doFinal(data);
    }


    public static byte[] des3_cbc(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(DES3_CBC_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, des3key(key), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    public static byte[] des_cbc(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(DES_CBC_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(resize_des(key, 8), "DES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    public static byte[] des_ecb(byte[] data, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(DES_ECB_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(resize_des(key, 8), "DES"));
        return cipher.doFinal(data);
    }

    public static byte[] des3_ecb(byte[] data, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(DES3_ECB_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, des3key(key));
        return cipher.doFinal(data);
    }

    // 3des mac over unpadded data
    public static byte[] mac_3des(byte[] text, byte[] key, byte[] iv) {
        try {
            byte[] d = pad80(text, 8);
            byte[] cgram = des3_cbc(d, key, iv);
            // rightmost 8 bytes
            return Arrays.copyOfRange(cgram, cgram.length - 8, cgram.length);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("MAC computation failed", e);
        }
    }

    // The weird mac used in SCP02, over unpadded data
    public static byte[] mac_des_3des(byte[] key, byte[] data, byte[] iv) {
        try {
            // Pad input data
            byte[] d = pad80(data, 8);

            // If payload is more than 8 bytes, do one pass of des_cbc of everything but the last 8 (padded) bytes
            // and use the rightmost 8 bytes of that as the IV for the full cbc.
            if (d.length > 8) {
                byte[] des = GPCrypto.des_cbc(Arrays.copyOf(d, d.length - 8), key, iv);
                iv = Arrays.copyOfRange(des, des.length - 8, des.length);
            }

            // Do des3_cbc of either last or only 8 bytes with the IV depending on payload length
            byte[] cgram = GPCrypto.des3_cbc(Arrays.copyOfRange(d, d.length - 8, d.length), key, iv);

            // Rightmost 8 bytes is the MAC
            return Arrays.copyOfRange(cgram, cgram.length - 8, cgram.length);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("MAC computation failed", e);
        }
    }

    // SCP03 related
    public static byte[] aes_cmac(byte[] key, byte[] data, int lengthBits) {
        // Use BouncyCastle light interface.
        BlockCipher cipher = AESEngine.newInstance();
        CMac cmac = new CMac(cipher);
        cmac.init(new KeyParameter(key));
        cmac.update(data, 0, data.length);
        byte[] out = new byte[cmac.getMacSize()];
        cmac.doFinal(out, 0);
        return Arrays.copyOf(out, lengthBits / 8);
    }

    public static byte[] scp03_kdf_blocka(byte constant, int blocklen_bits) {
        // 11 bytes
        byte[] label = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            bo.write(label); // 11 bytes of label
            bo.write(constant); // constant for the last byte
            bo.write(0x00); // separator
            bo.write((blocklen_bits >> 8) & 0xFF); // block size in two bytes
            bo.write(blocklen_bits & 0xFF);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return bo.toByteArray();
    }

    // GP 2.2.1 Amendment D v 1.1.1
    public static byte[] scp03_kdf(byte[] key, byte constant, byte[] context, int blocklen_bits) {
        byte[] blocka = scp03_kdf_blocka(constant, blocklen_bits);
        byte[] blockb = context;
        return scp03_kdf(key, blocka, blockb, blocklen_bits / 8);
    }

    // Generic KDF in counter mode with one byte counter.
    public static byte[] scp03_kdf(byte[] key, byte[] a, byte[] b, int bytes) {
        BlockCipher cipher = AESEngine.newInstance();
        CMac cmac = new CMac(cipher);
        KDFCounterBytesGenerator kdf = new KDFCounterBytesGenerator(cmac);
        kdf.init(new KDFCounterParameters(key, a, b, 8)); // counter size is in bits
        byte[] cgram = new byte[bytes];
        kdf.generateBytes(cgram, 0, cgram.length);
        return cgram;
    }

    // GPC 2.2.1 Amendment D 7.2.2
    public static byte[] kcv_aes(byte[] key) {
        try {
            return Arrays.copyOfRange(aes_cbc(one_bytes_16, key, new byte[16]), 0, 3);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Could not calculate KCV", e);
        }
    }

    // Some cards/vendors do KCV-s over 0x00 bytes, not 0x01 bytes
    public static byte[] kcv_aes0(byte[] key) {
        try {
            return Arrays.copyOfRange(aes_cbc(new byte[16], key, new byte[16]), 0, 3);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Could not calculate KCV", e);
        }
    }

    public static byte[] kcv_3des(byte[] key) {
        try {
            return Arrays.copyOf(des3_ecb(new byte[8], key), 3);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Could not calculate KCV", e);
        }
    }

    public static Key des3key(byte[] v) {
        return new SecretKeySpec(resize_des(v, 24), "DESede");
    }

    public static Key aeskey(byte[] v) {
        return new SecretKeySpec(v, "AES");
    }

    public static byte[] rsa_sign(RSAPrivateKey key, byte[] dtbs) throws GeneralSecurityException {
        int keylen = (key.getModulus().bitLength() + 7) / 8;
        if (keylen == 128) {
            return rsa_scheme1(key, dtbs);
        } else {
            return rsa_scheme2(key, dtbs);
        }
    }

    public static byte[] rsa_scheme2(RSAPrivateKey key, byte[] dtbs) throws GeneralSecurityException {
        // B.3.2 Scheme2 of RSA keys above 1k
        MGF1ParameterSpec mgf = MGF1ParameterSpec.SHA256;
        PSSParameterSpec spec = new PSSParameterSpec(mgf.getDigestAlgorithm(), "MGF1", mgf, 32, PSSParameterSpec.TRAILER_FIELD_BC);
        Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(spec);
        signer.initSign(key);
        signer.update(dtbs);
        return signer.sign();
    }

    public static byte[] rsa_scheme1(RSAPrivateKey key, byte[] dtbs) throws GeneralSecurityException {
        // B.3.1 Scheme1 of RSA keys up to 1k
        final Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(dtbs);
        return signer.sign();
    }

    // Get a public key from a PEM file, either public key or keypair
    public static PublicKey pem2PublicKey(InputStream in) throws IOException {
        try (PEMParser pem = new PEMParser(new InputStreamReader(in, StandardCharsets.US_ASCII))) {
            Object ohh = pem.readObject();
            if (ohh instanceof PEMKeyPair) {
                PEMKeyPair kp = (PEMKeyPair) ohh;
                return new JcaPEMKeyConverter().getKeyPair(kp).getPublic();
            } else if (ohh instanceof SubjectPublicKeyInfo) {
                return new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) ohh);
            } else if (ohh instanceof X509CertificateHolder) {
                X509CertificateHolder certHolder = (X509CertificateHolder) ohh;
                try {
                    return new JcaX509CertificateConverter().getCertificate(certHolder).getPublicKey();
                } catch (CertificateException ce) {
                    throw new IllegalArgumentException("Can not read PEM: " + ce.getMessage());
                }
            } else throw new IllegalArgumentException("Can not read PEM");
        }
    }

    // Get a private key from a PEM file, either private key or keypair
    public static PrivateKey pem2PrivateKey(InputStream in) throws IOException {
        try (PEMParser pem = new PEMParser(new InputStreamReader(in, StandardCharsets.US_ASCII))) {
            Object ohh = pem.readObject();
            if (ohh instanceof PEMKeyPair) {
                PEMKeyPair kp = (PEMKeyPair) ohh;
                return new JcaPEMKeyConverter().getKeyPair(kp).getPrivate();
            } else if (ohh instanceof PrivateKeyInfo) {
                return new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) ohh);
            } else throw new IllegalArgumentException("Can not read PEM");
        }
    }

    // Do shuffling as necessary
    static byte[] resize_des(byte[] key, int length) {
        switch (length) {
            case 24:
                return GPUtils.concatenate(Arrays.copyOf(key, 16), Arrays.copyOf(key, 8));
            case 8:
                return Arrays.copyOf(key, 8);
            default:
                throw new IllegalArgumentException("Invalid DES key length: " + length);
        }
    }

    // Convert DER to R||S
    public static byte[] der2rs(byte[] der, int len) throws SignatureException {
        try (ASN1InputStream input = new ASN1InputStream(der)) {
            DLSequence seq = (DLSequence) input.readObject();
            ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
            ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);
            return GPUtils.concatenate(leftpad(r.getPositiveValue().toByteArray(), len), leftpad(s.getPositiveValue().toByteArray(), len));
        } catch (IOException e) {
            throw new SignatureException("Could not convert DER to R||S: " + e.getMessage());
        }
    }

    // Right-align byte array to the specified size, padding with 0 from left
    public static byte[] leftpad(byte[] bytes, int len) {
        if (bytes.length < len) {
            byte[] nv = new byte[len];
            System.arraycopy(bytes, 0, nv, len - bytes.length, bytes.length);
            return nv;
        } else if (bytes.length > len) {
            byte[] nv = new byte[len];
            System.arraycopy(bytes, bytes.length - len, nv, 0, len);
            return nv;
        }
        return bytes;
    }
}
