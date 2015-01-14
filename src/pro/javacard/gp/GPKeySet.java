package pro.javacard.gp;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import pro.javacard.gp.GPData.KeyType;
import pro.javacard.gp.GPKeySet.GPKey.Type;
import apdu4j.HexUtils;

/**
 * GPKeySet encapsulates keys used for GP SCP operation.
 * It knows which key is used for what purpose and how to
 * diversify keys if needed.
 *
 */
public class GPKeySet {

	/**
	 * GPKey encapsulates a key used with GlobalPlatform.
	 * It either has value bytes available as plaintext
	 * or encapsulates a key from JCA (PKCS#11 etc)
	 */
	public static final class GPKey {
		// FIXME: set enum value to what is in GPData
		public enum Type {
			UNKNOWN, DES, DES3, AES
		}
		private int version = 0;
		private int id = 0;
		private int length = -1;
		private Type type = null;

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
		public Type getType() {
			return type;
		}

		public GPKey(int version, int id, GPKey ref) {
			this.version = version;
			this.id = id;
			this.type = ref.getType();
			this.length = ref.getLength();
			this.value = new byte[ref.getLength()];
			System.arraycopy(ref.getValue(), 0, value, 0, ref.getLength());
		}

		// Called when parsing KeyInfo template
		public GPKey(int version, int id, int length, int type) {
			this.version = version;
			this.id = id;
			this.length = length;
			// FIXME: these values should be encapsulated somewhere
			if (type == 0x80) {
				this.type = Type.DES3;
			} else if (type == 0x88) {
				this.type = Type.AES;
			} else {
				throw new RuntimeException(getClass().getName() + " currently only support DES and AES keys");
			}
		}


		// Create a key of given type and given bytes
		public GPKey(byte [] v, Type type) {
			if (v.length != 16 && v.length != 24  && v.length != 32)
				throw new IllegalArgumentException("A valid key should be 16/24/32 bytes long");
			this.value = new byte[v.length];
			System.arraycopy(v, 0, value, 0, v.length);
			this.length = v.length;
			this.type = type;

			// Set default ID/version
			id = 0x00;
			version = 0x00;
		}


		public Key getKey(Type type) {
			if (type == Type.DES) {
				return new SecretKeySpec(enlarge(value, 8), "DES");
			} else if (type == Type.DES3) {
				return new SecretKeySpec(enlarge(value, 24), "DESede");
			} else if (type == Type.AES) {
				return new SecretKeySpec(value, "AES");
			} else {
				throw new RuntimeException("Don't know how to handle " + type + " yet");
			}
		}

		public Key getKey() {
			return getKey(this.type);
		}

		public String toString() {
			return "Ver:" + version  + " ID:" + id + " Type:" + type + " Len:" + length + " Value:" + HexUtils.encodeHexString(value);
		}

		public String toStringKey() {
			return type + ":" + HexUtils.encodeHexString(value);
		}

	}

	public enum Diversification {
		NONE, VISA2, EMV
	}

	// A key set encapsulates a set of keys.
	private HashMap<KeyType, GPKey> keys = new HashMap<KeyType, GPKey>();
	// That all belong to the same set version
	private int keyVersion = 0x00;
	// With some cards, keys need to be diversified and derived from a master key
	public Diversification diversification = Diversification.NONE;
	private boolean diversified = false;

	// KeySet allows to access its keys
	public GPKey getKey(KeyType type) {
		return keys.get(type);
	}

	public Map<KeyType, GPKey> getKeys() {
		return new HashMap<KeyType, GPKey>(keys);
	}

	public Key getKeyFor(KeyType type) {
		return keys.get(type).getKey();
	}

	public int getVersion() {
		return keyVersion;
	}

	// KeyID
	private int keyID = 0x00;

	// Create an empty key set
	public GPKeySet() {

	}

	// Create a key set with all keys set to the master key
	// and using a given diversification method
	public GPKeySet(GPKey master, Diversification div) {
		// Diversification assumes 3DES keys
		keys.put(KeyType.ENC, master);
		keys.put(KeyType.MAC, master);
		keys.put(KeyType.KEK, master);
		this.diversification = div;
	}

	// A key set where all keys have the same value
	public GPKeySet(GPKey master) {
		this(master, Diversification.NONE);
	}

	public void setKey(KeyType type, GPKey k) {
		keys.put(type, k);
	}

	public void diversify(byte[] initialize_update_response, int scp) {
		// Sanity check.
		if (diversified || diversification == Diversification.NONE) {
			throw new IllegalStateException("Already diversified or not needed!");
		}

		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			for (KeyType v : KeyType.values()) {
				if (v == KeyType.RMAC)
					continue;
				byte [] kv = null;
				// shift around and fill initialize update data as required.
				if (diversification == Diversification.VISA2) {
					kv = fillVisa(initialize_update_response, v);
				} else if (diversification == Diversification.EMV) {
					kv = fillEmv(initialize_update_response, v);
				}

				// Encrypt with current master key
				cipher.init(Cipher.ENCRYPT_MODE, getKey(v).getKey(Type.DES3));

				byte [] keybytes = cipher.doFinal(kv);
				// Replace the key, possibly changing type. G&D SCE 6.0 uses EMV 3DES and resulting keys
				// must be interpreted as AES-128
				GPKey nk = new GPKey(keybytes, scp == 3 ? Type.AES : Type.DES3);
				keys.put(v, nk);
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

	@Override
	public String toString() {
		String s = "\nVersion " + getKeyVersion();
		s += "\nENC: " + getKey(KeyType.ENC);
		s += "\nMAC: " + getKey(KeyType.MAC);
		s += "\nKEK: " + getKey(KeyType.KEK);
		return s;
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

	private static byte[] enlarge(byte[] key, int length) {
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