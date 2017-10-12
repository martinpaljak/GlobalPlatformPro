package pro.javacard.gp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import pro.javacard.gp.GPKeySet.GPKey;
import pro.javacard.gp.GPKeySet.GPKey.Type;

public class GPCrypto {
	public static final byte[] null_bytes_8 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	public static final byte[] null_bytes_16 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	public static final byte[] one_bytes_16 = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

	// List of used ciphers.
	public static final String DES3_CBC_CIPHER = "DESede/CBC/NoPadding";
	public static final String DES3_ECB_CIPHER = "DESede/ECB/NoPadding";
	public static final String DES_CBC_CIPHER = "DES/CBC/NoPadding";
	public static final String DES_ECB_CIPHER = "DES/ECB/NoPadding";
	public static final String AES_CBC_CIPHER = "AES/CBC/NoPadding";

	public static final IvParameterSpec iv_null_des = new IvParameterSpec(null_bytes_8);
	public static final IvParameterSpec iv_null_aes = new IvParameterSpec(null_bytes_16);

	public static byte[] pad80(byte[] text, int offset, int length, int blocksize) {
		if (length == -1) {
			length = text.length - offset;
		}
		int totalLength = length;
		for (totalLength++; (totalLength % blocksize) != 0; totalLength++) {
			;
		}
		int padlength = totalLength - length;
		byte[] result = new byte[totalLength];
		System.arraycopy(text, offset, result, 0, length);
		result[length] = (byte) 0x80;
		for (int i = 1; i < padlength; i++) {
			result[length + i] = (byte) 0x00;
		}
		return result;
	}

	public static byte[] pad80(byte[] text, int blocksize) {
		return pad80(text, 0, text.length, blocksize);
	}

	private static void buffer_increment(byte[] buffer, int offset, int len) {
		if (len < 1)
			return;
		for (int i=offset+len-1; i >= offset; i--) {
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
	public static byte[] mac_3des(GPKey key, byte[] text, byte[] iv)  {
		byte [] d = pad80(text, 8);
		return mac_3des(key.getKey(), d, 0, d.length, iv);
	}
	// 3des mac with null iv
	public static byte[] mac_3des_nulliv(GPKey key, byte[] d) {
		return mac_3des(key, d, null_bytes_8);
	}
	static byte[] mac_3des(Key key, byte[] text, int offset, int length, byte[] iv) {
		if (length == -1) {
			length = text.length - offset;
		}

		try {
			Cipher cipher = Cipher.getInstance(DES3_CBC_CIPHER);
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			byte[] result = new byte[8];
			byte[] res = cipher.doFinal(text, offset, length);
			System.arraycopy(res, res.length - 8, result, 0, 8);
			return result;
		} catch (Exception e) {
			throw new RuntimeException("MAC computation failed.", e);
		}
	}

	// The weird mac
	public static byte[] mac_des_3des(GPKey key, byte[] text, byte[] iv) {
		byte [] d = pad80(text, 8);
		return mac_des_3des(key, d, 0, d.length, iv);
	}

	private static byte[] mac_des_3des(GPKey key, byte[] text, int offset, int length, byte[] iv) {
		if (length == -1) {
			length = text.length - offset;
		}

		try {

			Cipher cipher1 = Cipher.getInstance(DES_CBC_CIPHER);
			cipher1.init(Cipher.ENCRYPT_MODE, key.getKey(Type.DES), new IvParameterSpec(iv));
			Cipher cipher2 = Cipher.getInstance(DES3_CBC_CIPHER);
			cipher2.init(Cipher.ENCRYPT_MODE, key.getKey(Type.DES3), new IvParameterSpec(iv));

			byte[] result = new byte[8];
			byte[] temp;

			if (length > 8) {
				temp = cipher1.doFinal(text, offset, length - 8);
				System.arraycopy(temp, temp.length - 8, result, 0, 8);
				cipher2.init(Cipher.ENCRYPT_MODE, key.getKey(Type.DES3), new IvParameterSpec(result));
			}
			temp = cipher2.doFinal(text, (offset + length) - 8, 8);
			System.arraycopy(temp, temp.length - 8, result, 0, 8);
			return result;
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("MAC computation failed.", e);
		}
	}

	// SCP03 related
	public static byte[] scp03_mac(GPKey key, byte[] msg, int lengthbits) {
		return scp03_mac(key.getValue(), msg, lengthbits);
	}
	public static byte[] scp03_mac(byte[] keybytes, byte[] msg, int lengthBits) {
		// Use BouncyCastle light interface. Maybe use JCE and deal with ProGuard?
		// FIXME: programmatically set the crypto backend
		BlockCipher cipher = new AESEngine();
		CMac cmac = new CMac(cipher);
		cmac.init(new KeyParameter(keybytes));
		cmac.update(msg, 0, msg.length);
		byte[] out = new byte[cmac.getMacSize()];
		cmac.doFinal(out, 0);
		return Arrays.copyOf(out, lengthBits/8);
	}

	// GP 2.2.1 Amendment D v 1.1.1
	public static byte [] scp03_kdf(GPKey key, byte constant, byte[] context, int blocklen_bits) {
		return scp03_kdf(key.getValue(), constant, context, blocklen_bits);
	}

	private static byte [] scp03_kdf(byte [] key, byte constant, byte[] context, int blocklen_bits) {
		// 11 bytes
		byte [] label = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

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
		byte [] blocka = bo.toByteArray();
		byte [] blockb = context;

		BlockCipher cipher = new AESEngine();
		CMac cmac = new CMac(cipher);
		KDFCounterBytesGenerator kdf = new KDFCounterBytesGenerator(cmac);
		kdf.init(new KDFCounterParameters(key, blocka, blockb, 8)); // counter size in bits

		byte[] cgram  = new byte[blocklen_bits/8];
		kdf.generateBytes(cgram, 0, cgram.length);
		return cgram;
	}

	public static byte[] scp03_key_check_value(GPKey key) {
		try {
			Cipher c = Cipher.getInstance(AES_CBC_CIPHER);
			c.init(Cipher.ENCRYPT_MODE, key.getKey(), iv_null_aes);
			byte[] cv = c.doFinal(one_bytes_16);
			return Arrays.copyOfRange(cv, 0, 3);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (BadPaddingException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		}
	}

	public static byte[] scp03_encrypt_key(GPKey kek, GPKey key) {
		try {
			// Pad with random
			int n = key.getLength() % 16 + 1;
			byte [] plaintext = new byte[n*16];
			SecureRandom sr = new SecureRandom();
			sr.nextBytes(plaintext);
			System.arraycopy(key.getValue(), 0, plaintext, 0, key.getLength());
			// encrypt
			Cipher c = Cipher.getInstance(AES_CBC_CIPHER);
			c.init(Cipher.ENCRYPT_MODE, kek.getKey(), iv_null_aes);
			byte[] cgram = c.doFinal(plaintext);
			return cgram;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (BadPaddingException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException("Could not calculate key check value: ", e);
		}
	}

	public static byte[] kcv_3des(GPKey key) {
		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, key.getKey());
			byte check[] = cipher.doFinal(GPCrypto.null_bytes_8);
			return Arrays.copyOf(check, 3);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException("Could not calculate KCV", e);
		}
	}
}
