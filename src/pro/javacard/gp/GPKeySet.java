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

import java.security.Key;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import apdu4j.HexUtils;
import pro.javacard.gp.GPData.KeyType;

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
			ANY, DES, DES3, AES
		}
		private int version = 0;
		private int id = 0;
		private int length = -1;
		private final Type type;
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
			// FIXME: 0x81 is actually reserved according to GP
			if (type == 0x80 || type == 0x81) {
				this.type = Type.DES3;
			} else if (type == 0x88) {
				this.type = Type.AES;
			} else {
				throw new IllegalArgumentException(getClass().getName() + " currently only supports 3DES and AES keys");
			}
		}


		// Create a key of given type and given bytes
		public GPKey(byte [] v, Type type) {
			if (v.length != 16 && v.length != 24  && v.length != 32)
				throw new IllegalArgumentException("A valid key should be 16/24/32 bytes long");
			this.value = Arrays.copyOf(v, v.length);
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
				throw new IllegalArgumentException("Don't know how to handle " + type + " yet");
			}
		}

		public Key getKey() {
			return getKey(this.type);
		}

		public String toString() {
			return "Ver:" + version  + " ID:" + id + " Type:" + type + " Len:" + length + " Value:" + HexUtils.bin2hex(value) + " KCV: " + HexUtils.bin2hex(getKCV());
		}

		public String toStringKey() {
			return type + ":" + HexUtils.bin2hex(value);
		}

		public byte[] getKCV() {
			if (type == Type.DES3) {
				return GPCrypto.kcv_3des(this);
			} else if (type == Type.AES) {
				return GPCrypto.scp03_key_check_value(this);
			} else {
				return new byte[0];
			}
		}
	}

	// diversification methods
	public enum Diversification {
		NONE, VISA2, EMV
	}

	// A key set encapsulates a set of keys.
	private HashMap<KeyType, GPKey> keys = new HashMap<KeyType, GPKey>();
	// That all belong to the same set version
	private int keyVersion = 0x00;

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
	public GPKeySet(GPKey master) {
		keys.put(KeyType.ENC, master);
		keys.put(KeyType.MAC, master);
		keys.put(KeyType.KEK, master);
	}

	public GPKeySet(GPKey enc, GPKey mac, GPKey kek) {
		keys.put(KeyType.ENC, enc);
		keys.put(KeyType.MAC, mac);
		keys.put(KeyType.KEK, kek);
	}

	public void setKey(KeyType type, GPKey k) {
		keys.put(type, k);
	}


	@Override
	public String toString() {
		String s = "\nENC: " + getKey(KeyType.ENC);
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