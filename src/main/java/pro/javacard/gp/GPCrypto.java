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

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import pro.javacard.gp.GPKey.Type;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

// Various cryptographic primitives used for secure channel or plaintext keys
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
    public static byte[] mac_3des(GPKey key, byte[] text, byte[] iv) {
        byte[] d = pad80(text, 8);
        return mac_3des(key.getKeyAs(Type.DES3), d, 0, d.length, iv);
    }

    // 3des mac with null iv
    public static byte[] mac_3des_nulliv(GPKey key, byte[] d) {
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
    public static byte[] mac_des_3des(GPKey key, byte[] text, byte[] iv) {
        byte[] d = pad80(text, 8);
        return mac_des_3des(key, d, 0, d.length, iv);
    }

    private static byte[] mac_des_3des(GPKey key, byte[] text, int offset, int length, byte[] iv) {
        try {
            Cipher cipher1 = Cipher.getInstance(DES_CBC_CIPHER);
            cipher1.init(Cipher.ENCRYPT_MODE, key.getKeyAs(Type.DES), new IvParameterSpec(iv));
            Cipher cipher2 = Cipher.getInstance(DES3_CBC_CIPHER);
            cipher2.init(Cipher.ENCRYPT_MODE, key.getKeyAs(Type.DES3), new IvParameterSpec(iv));

            byte[] result = new byte[8];
            byte[] temp;

            if (length > 8) {
                temp = cipher1.doFinal(text, offset, length - 8);
                System.arraycopy(temp, temp.length - 8, result, 0, 8);
                cipher2.init(Cipher.ENCRYPT_MODE, key.getKeyAs(Type.DES3), new IvParameterSpec(result));
            }
            temp = cipher2.doFinal(text, (offset + length) - 8, 8);
            System.arraycopy(temp, temp.length - 8, result, 0, 8);
            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("MAC computation failed.", e);
        }
    }

    // SCP03 related
    public static byte[] scp03_mac(GPKey key, byte[] msg, int lengthbits) {
        return scp03_mac(key.getBytes(), msg, lengthbits);
    }

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
    public static byte[] scp03_kdf(GPKey key, byte constant, byte[] context, int blocklen_bits) {
        return scp03_kdf(key.getBytes(), constant, context, blocklen_bits);
    }

    private static byte[] scp03_kdf(byte[] key, byte constant, byte[] context, int blocklen_bits) {
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
    public static byte[] scp03_key_check_value(GPKey key) {
        try {
            Cipher c = Cipher.getInstance(AES_CBC_CIPHER);
            c.init(Cipher.ENCRYPT_MODE, key.getKeyAs(Type.AES), iv_null_16);
            byte[] cv = c.doFinal(one_bytes_16);
            return Arrays.copyOfRange(cv, 0, 3);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Could not calculate KCV", e);
        }
    }

    public static byte[] scp03_encrypt_key(GPKey dek, GPKey key) {
        try {
            // Pad with random
            int n = key.getLength() % 16 + 1;
            byte[] plaintext = new byte[n * key.getLength()];
            random.nextBytes(plaintext);
            System.arraycopy(key.getBytes(), 0, plaintext, 0, key.getLength());
            // encrypt
            Cipher c = Cipher.getInstance(AES_CBC_CIPHER);
            c.init(Cipher.ENCRYPT_MODE, dek.getKeyAs(Type.AES), iv_null_16);
            byte[] cgram = c.doFinal(plaintext);
            return cgram;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Could not encrypt key", e);
        }
    }

    public static byte[] kcv_3des(GPKey key) {
        try {
            Cipher cipher = Cipher.getInstance(DES3_ECB_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key.getKeyAs(Type.DES3));
            byte check[] = cipher.doFinal(GPCrypto.null_bytes_8);
            return Arrays.copyOf(check, 3);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Could not calculate KCV", e);
        }
    }

    // Get a public key from a PEM file, either public key or keypair
    public static PublicKey pem2pubkey(InputStream in) throws IOException {
        try (PEMParser pem = new PEMParser(new InputStreamReader(in, StandardCharsets.US_ASCII))) {
            Object ohh = pem.readObject();
            if (ohh instanceof PEMKeyPair) {
                PEMKeyPair kp = (PEMKeyPair) ohh;
                return new JcaPEMKeyConverter().getKeyPair(kp).getPublic();
            } else if (ohh instanceof SubjectPublicKeyInfo) {
                return new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) ohh);
            } else throw new IllegalArgumentException("Can not read PEM");
        }
    }
}
