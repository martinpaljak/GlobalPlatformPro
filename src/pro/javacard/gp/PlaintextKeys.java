/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2016 Martin Paljak, martin@martinpaljak.net
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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pro.javacard.gp.GPData.KeyType;
import pro.javacard.gp.GPKeySet.Diversification;
import pro.javacard.gp.GPKeySet.GPKey;
import pro.javacard.gp.GPKeySet.GPKey.Type;

public class PlaintextKeys implements SessionKeyProvider {
	// not static to allow configuration in tool
	private Logger logger = LoggerFactory.getLogger(PlaintextKeys.class);

	private final GPKeySet staticKeys;
	final Diversification diversifier;
	protected GPKey master; // For use in GPTool

	private PlaintextKeys(GPKeySet keys, Diversification div) {
		staticKeys = keys;
		diversifier = div;
		logger.debug("static keys: {}", staticKeys.toString());
	}

	@Override
	public GPKeySet getSessionKeys(int scp, byte[] kdd, byte[]... args) throws GPException  {
		GPKeySet cardKeys = staticKeys;

		// Diversify if needed
		if (diversifier != Diversification.NONE) {
			cardKeys = diversify(staticKeys, kdd, diversifier, scp);
			logger.debug("card keys: {}", cardKeys.toString());
		}
		GPKeySet sessionKeys;
		if (scp == 1) {
			if (args.length != 2) {
				throw new IllegalArgumentException("SCP01 requires host challenge and card challenge");
			}
			sessionKeys = deriveSessionKeysSCP01(cardKeys, args[0], args[1]);
		} else if (scp == 2) {
			if (args.length != 1) {
				throw new IllegalArgumentException("SCP02 requires sequence");
			}
			sessionKeys = deriveSessionKeysSCP02(cardKeys, args[0], false);
		} else if (scp == 3) {
			if (args.length != 2) {
				throw new IllegalArgumentException("SCP03 requires host challenge and card challenge");
			}
			sessionKeys = deriveSessionKeysSCP03(cardKeys, args[0], args[1]);
		} else {
			throw new IllegalArgumentException("Dont know how to handle: " + scp);
		}
		logger.debug("session keys: {}", sessionKeys.toString());
		return sessionKeys;
	}

	public static GPKeySet diversify(GPKeySet keys, byte[] diversification_data, Diversification mode, int scp) throws GPException {
		try {
			GPKeySet result = new GPKeySet();
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			for (KeyType v : KeyType.values()) {
				if (v == KeyType.RMAC)
					continue;
				byte [] kv = null;
				// shift around and fill initialize update data as required.
				if (mode == Diversification.VISA2) {
					kv = fillVisa(diversification_data, v);
				} else if (mode == Diversification.EMV) {
					kv = fillEmv(diversification_data, v);
				}

				// Encrypt with current master key
				cipher.init(Cipher.ENCRYPT_MODE, keys.getKey(v).getKey(Type.DES3));

				byte [] keybytes = cipher.doFinal(kv);
				// Replace the key, possibly changing type. G&D SCE 6.0 uses EMV 3DES and resulting keys
				// must be interpreted as AES-128
				GPKey nk = new GPKey(keybytes, scp == 3 ? Type.AES : Type.DES3);
				result.setKey(v, nk);
			}
			return result;
		} catch (BadPaddingException |InvalidKeyException | IllegalBlockSizeException e) {
			throw new GPException("Diversification failed.", e);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new RuntimeException("Diversification failed.", e);
		}
	}

	public static byte[] fillVisa(byte[] init_update_response, KeyType key) {
		byte[] data = new byte[16];
		System.arraycopy(init_update_response, 0, data, 0, 2);
		System.arraycopy(init_update_response, 4, data, 2, 4);
		data[6] = (byte) 0xF0;
		data[7] = key.getValue();
		System.arraycopy(init_update_response, 0, data, 8, 2);
		System.arraycopy(init_update_response, 4, data, 10, 4);
		data[14] = (byte) 0x0F;
		data[15] = key.getValue();
		return data;
	}

	public static byte[] fillVisa2(byte[] init_update_response, KeyType key) {
		byte[] data = new byte[16];
		System.arraycopy(init_update_response, 0, data, 0, 4);
		System.arraycopy(init_update_response, 8, data, 4, 2);
		data[6] = (byte) 0xF0;
		data[7] = 0x01;
		System.arraycopy(init_update_response, 0, data, 8, 4);
		System.arraycopy(init_update_response, 8, data, 12, 2);
		data[14] = (byte) 0x0F;
		data[15] = 0x01;
		return data;
	}

	public static byte[] fillEmv(byte[] init_update_response, KeyType key) {
		byte[] data = new byte[16];
		// 6 rightmost bytes of init update response (which is 10 bytes)
		System.arraycopy(init_update_response, 4, data, 0, 6);
		data[6] = (byte) 0xF0;
		data[7] = key.getValue();
		System.arraycopy(init_update_response, 4, data, 8, 6);
		data[14] = (byte) 0x0F;
		data[15] = key.getValue();
		return data;

	}


	public static PlaintextKeys fromMasterKey(GPKey master, Diversification div) {
		GPKeySet ks = new GPKeySet(master);
		PlaintextKeys p = new PlaintextKeys(ks, div);
		p.master = master;
		return p;
	}
	public static PlaintextKeys fromMasterKey(GPKey master) {
		return fromMasterKey(master, Diversification.NONE);
	}

	public static PlaintextKeys fromKeySet(GPKeySet ks) {
		return new PlaintextKeys(ks, Diversification.NONE);
	}

	@Override
	public int getKeysetVersion() {
		return staticKeys.getKeyVersion();
	}


	@Override
	public int getKeysetID() {
		return staticKeys.getKeyID();
	}


	private GPKeySet deriveSessionKeysSCP01(GPKeySet staticKeys, byte[] host_challenge, byte[] card_challenge) {
		GPKeySet sessionKeys = new GPKeySet();

		byte[] derivationData = new byte[16];
		System.arraycopy(card_challenge, 4, derivationData, 0, 4);
		System.arraycopy(host_challenge, 0, derivationData, 4, 4);
		System.arraycopy(card_challenge, 0, derivationData, 8, 4);
		System.arraycopy(host_challenge, 4, derivationData, 12, 4);

		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			for (KeyType v: KeyType.values()) {
				if (v == KeyType.RMAC) // skip RMAC key
					continue;
				cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(v));
				GPKey nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
				sessionKeys.setKey(v, nk);
			}
			// KEK is the same
			sessionKeys.setKey(KeyType.KEK, staticKeys.getKey(KeyType.KEK));
			return sessionKeys;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new IllegalStateException("Session keys calculation failed.", e);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		}
	}


	private GPKeySet deriveSessionKeysSCP02(GPKeySet staticKeys, byte[] sequence, boolean implicitChannel) {
		GPKeySet sessionKeys = new GPKeySet();

		try {
			Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");

			byte[] derivationData = new byte[16];
			System.arraycopy(sequence, 0, derivationData, 2, 2);

			byte[] constantMAC = new byte[] { (byte) 0x01, (byte) 0x01 };
			System.arraycopy(constantMAC, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(KeyType.MAC), GPCrypto.iv_null_des);
			GPKey nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
			sessionKeys.setKey(KeyType.MAC, nk);

			// TODO: is this correct? - increment by one for all other than C-MAC
			if (implicitChannel) {
				TLVUtils.buffer_increment(derivationData, 2, 2);
			}

			byte[] constantRMAC = new byte[] { (byte) 0x01, (byte) 0x02 };
			System.arraycopy(constantRMAC, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(KeyType.MAC), GPCrypto.iv_null_des);
			nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
			sessionKeys.setKey(KeyType.RMAC, nk);


			byte[] constantENC = new byte[] { (byte) 0x01, (byte) 0x82 };
			System.arraycopy(constantENC, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(KeyType.ENC), GPCrypto.iv_null_des);
			nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
			sessionKeys.setKey(KeyType.ENC, nk);

			byte[] constantDEK = new byte[] { (byte) 0x01, (byte) 0x81 };
			System.arraycopy(constantDEK, 0, derivationData, 0, 2);
			cipher.init(Cipher.ENCRYPT_MODE, staticKeys.getKeyFor(KeyType.KEK), GPCrypto.iv_null_des);
			nk = new GPKey(cipher.doFinal(derivationData), Type.DES3);
			sessionKeys.setKey(KeyType.KEK, nk);
			return sessionKeys;

		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new IllegalStateException("Session keys calculation failed.", e);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException("Session keys calculation failed.", e);
		}
	}


	private GPKeySet deriveSessionKeysSCP03(GPKeySet staticKeys, byte[] host_challenge, byte[] card_challenge) {
		GPKeySet sessionKeys = new GPKeySet();
		final byte mac_constant = 0x06;
		final byte enc_constant = 0x04;
		final byte rmac_constant = 0x07;

		byte []context = GPUtils.concatenate(host_challenge, card_challenge);

		// MAC
		byte []kdf = GPCrypto.scp03_kdf(staticKeys.getKey(KeyType.MAC), mac_constant, context, 128);
		sessionKeys.setKey(KeyType.MAC, new GPKey(kdf, Type.AES));
		// ENC
		kdf = GPCrypto.scp03_kdf(staticKeys.getKey(KeyType.ENC), enc_constant, context, 128);
		sessionKeys.setKey(KeyType.ENC, new GPKey(kdf, Type.AES));
		// RMAC
		kdf = GPCrypto.scp03_kdf(staticKeys.getKey(KeyType.MAC), rmac_constant, context, 128);
		sessionKeys.setKey(KeyType.RMAC, new GPKey(kdf, Type.AES));

		// KEK remains the same
		sessionKeys.setKey(KeyType.KEK, staticKeys.getKey(KeyType.KEK));
		return sessionKeys;
	}

}
