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
import java.util.Arrays;

// Various cryptographic primitives used for secure channel or plaintext keys
@SuppressWarnings("lgtm[java/weak-cryptographic-algorithm]")
public final class GPCrypto {
    static final byte[] null_bytes_8 = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static final byte[] null_bytes_16 = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static final byte[] one_bytes_16 = new byte[]{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    // List of used ciphers.
    static final String DES3_CBC_CIPHER = "DESede/CBC/NoPadding";
    static final String DES3_ECB_CIPHER = "DESede/ECB/NoPadding";
    static final String DES_CBC_CIPHER = "DES/CBC/NoPadding";
    static final String DES_ECB_CIPHER = "DES/ECB/NoPadding";
    static final String AES_CBC_CIPHER = "AES/CBC/NoPadding";

    static final IvParameterSpec iv_null_8 = new IvParameterSpec(null_bytes_8);
    static final IvParameterSpec iv_null_16 = new IvParameterSpec(null_bytes_16);

    // Shared random
    static final SecureRandom random;

    static {
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
            random.nextBytes(new byte[2]); // Force seeding
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Need SecureRandom to run");
        }
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

    // 3des mac
    public static byte[] mac_3des(byte[] key, byte[] text, byte[] iv) {
        byte[] d = pad80(text, 8);
        return mac_3des(new SecretKeySpec(resizeDES(key, 24), "DESede"), d, 0, d.length, iv);
    }


    public static byte[] mac_3des_nulliv(byte[] key, byte[] d) {
        return mac_3des(key, d, null_bytes_8);
    }

    static byte[] mac_3des(Key key, byte[] text, int offset, int length, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(DES3_CBC_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] result = new byte[8];
            byte[] res = cipher.doFinal(text, offset, length);
            System.arraycopy(res, res.length - 8, result, 0, 8);
            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("MAC computation failed.", e);
        }
    }

    // The weird mac
    public static byte[] mac_des_3des(byte[] key, byte[] text, byte[] iv) {
        byte[] d = pad80(text, 8);
        return mac_des_3des(key, d, 0, d.length, iv);
    }

    private static byte[] mac_des_3des(byte[] key, byte[] text, int offset, int length, byte[] iv) {
        try {
            Cipher cipher1 = Cipher.getInstance(DES_CBC_CIPHER);
            cipher1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(resizeDES(key, 8), "DES"), new IvParameterSpec(iv));
            Cipher cipher2 = Cipher.getInstance(DES3_CBC_CIPHER);
            cipher2.init(Cipher.ENCRYPT_MODE, des3key(key), new IvParameterSpec(iv));

            byte[] result = new byte[8];
            byte[] temp;

            if (length > 8) {
                temp = cipher1.doFinal(text, offset, length - 8);
                System.arraycopy(temp, temp.length - 8, result, 0, 8);
                cipher2.init(Cipher.ENCRYPT_MODE, des3key(key), new IvParameterSpec(result));
            }
            temp = cipher2.doFinal(text, (offset + length) - 8, 8);
            System.arraycopy(temp, temp.length - 8, result, 0, 8);
            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("MAC computation failed.", e);
        }
    }

    // SCP03 related
    public static byte[] scp03_mac(byte[] keybytes, byte[] msg, int lengthBits) {
        // Use BouncyCastle light interface.
        BlockCipher cipher = new AESEngine();
        CMac cmac = new CMac(cipher);
        cmac.init(new KeyParameter(keybytes));
        cmac.update(msg, 0, msg.length);
        byte[] out = new byte[cmac.getMacSize()];
        cmac.doFinal(out, 0);
        return Arrays.copyOf(out, lengthBits / 8);
    }

    // GP 2.2.1 Amendment D v 1.1.1
    static byte[] scp03_kdf(byte[] key, byte constant, byte[] context, int blocklen_bits) {
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
        byte[] blocka = bo.toByteArray();
        byte[] blockb = context;
        return scp03_kdf(key, blocka, blockb, blocklen_bits / 8);
    }

    // Generic KDF in counter mode with one byte counter.
    public static byte[] scp03_kdf(byte[] key, byte[] a, byte[] b, int bytes) {
        BlockCipher cipher = new AESEngine();
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
            Cipher c = Cipher.getInstance(AES_CBC_CIPHER);
            c.init(Cipher.ENCRYPT_MODE, aeskey(key), iv_null_16);
            byte[] cv = c.doFinal(one_bytes_16);
            return Arrays.copyOfRange(cv, 0, 3);
        } catch (GeneralSecurityException e) {
            throw new GPException("Could not calculate KCV", e);
        }
    }

    public static byte[] kcv_aes0(byte[] key) {
        try {
            Cipher c = Cipher.getInstance(AES_CBC_CIPHER);
            c.init(Cipher.ENCRYPT_MODE, aeskey(key), iv_null_16);
            byte[] cv = c.doFinal(null_bytes_16);
            return Arrays.copyOfRange(cv, 0, 3);
        } catch (GeneralSecurityException e) {
            throw new GPException("Could not calculate KCV", e);
        }
    }

    public static byte[] kcv_3des(byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance(DES3_ECB_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, des3key(key));
            byte[] check = cipher.doFinal(GPCrypto.null_bytes_8);
            return Arrays.copyOf(check, 3);
        } catch (GeneralSecurityException e) {
            throw new GPException("Could not calculate KCV", e);
        }
    }

    public static Key des3key(byte[] v) {
        return new SecretKeySpec(resizeDES(v, 24), "DESede");
    }

    public static Key aeskey(byte[] v) {
        return new SecretKeySpec(v, "AES");
    }

    public static byte[] dek_encrypt_des(byte[] key, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(DES3_ECB_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, des3key(key));
        return cipher.doFinal(data);
    }

    public static byte[] dek_encrypt_aes(byte[] key, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_CBC_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, aeskey(key), iv_null_16);
        return cipher.doFinal(data);
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
    static byte[] resizeDES(byte[] key, int length) {
        if (length == 24) {
            byte[] key24 = new byte[24];
            System.arraycopy(key, 0, key24, 0, 16);
            System.arraycopy(key, 0, key24, 16, 8);
            return key24;
        } else {
            byte[] key8 = new byte[8];
            System.arraycopy(key, 0, key8, 0, 8);
            return key8;
        }
    }
}
