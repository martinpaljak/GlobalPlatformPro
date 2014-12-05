package openkms.gp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class KeySet {


	public static final class Key {
		private int version = 0;
		private int id = 0;
		private int length = -1;
		private int type = -1;

		private byte [] value = null;
		public int getID() {
			return id;
		}
		public int getVersion() {
			return version;
		}
		public byte[] getValue() {
			return value;
		}
		public int getLength() {
			return length;
		}

		public Key(int version, int id, byte[] value) {
			this.version = version;
			this.id = id;
			this.value = value;
			this.length = value.length;
		}

		public Key(int version, int id, int length, int type) {
			this.version = version;
			this.id = id;
			this.length = length;
			this.type = type;
		}

		public Key(String s) {
			this.value = GPUtils.stringToByteArray(s);
			if (this.value.length != 16)
				throw new IllegalArgumentException("3DES key must be 16 bytes long");
			this.id = 0x00;
			this.version = 0x00;
		}

		public String toString() {
			return "ID:" + this.id + " Ver:" + this.version + " Value:" + GPUtils.byteArrayToString(this.value);
		}
	}

	public enum KeyType {
		// ID is as used in diversification/derivation
		// That is - one based.
		ENC(1), MAC(2), KEK(3), RMAC(4);

		private final int value;

		private KeyType(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}
	};

	public enum KeyDiversification {
		NONE, VISA2, EMV
	};

	byte[] enc_key = null;
	byte[] mac_key = null;
	byte[] kek_key = null;
	byte[] rmac_key = null;

	// KeyID
	private int keyID = 0x00;
	private int keyVersion = 0x00;

	public KeyDiversification diversification = KeyDiversification.NONE;
	private boolean diversified = false;

	public KeySet() {
	}

	public KeySet(byte[] masterKey, KeyDiversification diversification) {
		this(masterKey, masterKey, masterKey);
		this.diversification = diversification;
	}

	public KeySet(Key masterKey) {
		this(masterKey.getValue(), masterKey.getValue(), masterKey.getValue());
	}
	public KeySet(byte[] masterKey) {
		this(masterKey, masterKey, masterKey);
	}

	public KeySet(byte[] encKey, byte[] macKey, byte[] kekKey) {
		setKey(KeyType.ENC, encKey);
		setKey(KeyType.MAC, macKey);
		setKey(KeyType.KEK, kekKey);
	}
	public void setKey(KeyType type, Key value) {
		setKey(type, value.getValue());
	}
	public void setKey(KeyType type, byte[] value) {
		if (value.length < 16)
			throw new IllegalArgumentException("Key must be at least 16 bytes");
		switch (type) {
			case ENC:
				enc_key = value;
				break;
			case MAC:
				mac_key = value;
				break;
			case KEK:
				kek_key = value;
				break;
			case RMAC:
				rmac_key = value;
				break;
			default:
				break;
		}
	}

	public byte[] getKey(KeyType type) {
		switch (type) {
			case ENC:
				return enc_key;
			case MAC:
				return mac_key;
			case KEK:
				return kek_key;
			case RMAC:
				return rmac_key;
			default:
				return null;
		}
	}

	public java.security.Key get3DESKey(KeyType type) {
		return new SecretKeySpec(getKey(getKey(type), 24), "DESede");
	}

	public java.security.Key getDESKey(KeyType type) {
		return new SecretKeySpec(getKey(getKey(type), 8), "DES");
	}

	private byte[] get3DES(KeyType type) {
		byte[] key24 = new byte[24];
		System.arraycopy(getKey(type), 0, key24, 0, 16);
		System.arraycopy(getKey(type), 0, key24, 16, 8);
		return key24;
	}

	private byte[] getDES(KeyType type) {
		byte[] key8 = new byte[8];
		System.arraycopy(getKey(type), 0, key8, 0, 8);
		return key8;
	}

	public KeySet(int keyVersion, int keyID, byte[] encKey, byte[] macKey, byte[] kekKey, KeyDiversification diversification) {
		this(encKey, macKey, kekKey);
		this.diversification = diversification;
		this.keyID = keyID;
		this.keyVersion = keyVersion;
	}

	public boolean needsDiversity() {
		return diversification != KeyDiversification.NONE && !diversified;
	}
	public void diversify(byte[] initialize_update_response) {
		if (diversified || diversification == KeyDiversification.NONE) {
			throw new IllegalStateException("Already diversified or not needed!");
		}

		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			byte[] data = new byte[16];
			for (KeyType v : KeyType.values()) {
				if (v == KeyType.RMAC)
					continue;

				// shift around and fill initialize update data as required.
				if (diversification == KeyDiversification.VISA2) {
					fillVisa(data, initialize_update_response, v);
				} else if (diversification == KeyDiversification.EMV) {
					fillEmv(data, initialize_update_response, v);
				}

				// Encrypt with current master key
				cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(get3DES(v), "DESede"));

				// Replace the key
				setKey(v, cipher.doFinal(data));
			}

			diversified = true;
		} catch (BadPaddingException e) {
			throw new RuntimeException("Diversification failed.", e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Diversification failed.", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Diversification failed.", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Diversification failed.", e);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Diversification failed.", e);
		}
	}

	private void fillVisa(byte[] data, byte[] init_update_response, KeyType key) {
		System.arraycopy(init_update_response, 0, data, 0, 2);
		System.arraycopy(init_update_response, 4, data, 2, 4);
		data[6] = (byte) 0xF0;
		data[7] = (byte) key.value;
		System.arraycopy(init_update_response, 0, data, 8, 2);
		System.arraycopy(init_update_response, 4, data, 10, 4);
		data[14] = (byte) 0x0F;
		data[15] = (byte) key.value;
	}

	private void fillEmv(byte[] data, byte[] init_update_response, KeyType key) {
		// 6 rightmost bytes of init update response (which is 10 bytes)
		System.arraycopy(init_update_response, 4, data, 0, 6);
		data[6] = (byte) 0xF0;
		data[7] = (byte) key.value;
		System.arraycopy(init_update_response, 4, data, 8, 6);
		data[14] = (byte) 0x0F;
		data[15] = (byte) key.value;
	}

	@Override
	public String toString() {
		return new String("\nENC: " + GPUtils.byteArrayToString(getKey(KeyType.ENC)) + "\nMAC: "
				+ GPUtils.byteArrayToString(getKey(KeyType.MAC)) + "\nKEK: " + GPUtils.byteArrayToString(getKey(KeyType.KEK)));
	}

	public int getKeyID() {
		return keyID;
	}

	public int getKeyVersion() {
		return keyVersion;
	}

	public void setKeyID(int keyID) {
		this.keyID = keyID;
	}

	public void setKeyVersion(int keyVersion) {
		this.keyVersion = keyVersion;
	}

	protected static byte[] getKey(byte[] key, int length) {
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