package openkms.gpj;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


public class KeySet {
	
	public enum KeyType {
		ENC(0), MAC(1), KEK(2);
		
		private final int value;
		private KeyType(int value) {
	        this.value = value;
	    }

	    public int getValue() {
	        return value;
	    }
	};

	// Diversification method, if applicable.
	public static final int NONE = 0;
	public static final int VISA2 = 1;
	public static final int EMV = 2;

	// index in the keys array for a given key
	public static final int KEY_ENC = 0;
	public static final int KEY_MAC = 1;
	public static final int KEY_KEK = 2;
	
	// KeyID
	private int keyID = 0x00;
	private int keyVersion = 0x00;

	int diversification = NONE;
	private boolean diversified = false;

	byte[][] keys = null;

	public KeySet() {
		keys = new byte[][] { null, null, null, null };
	}

	public KeySet(byte[] encKey, byte[] macKey, byte[] kekKey) {
		keys = new byte[][] { encKey, macKey, kekKey };
	}


	public KeySet(byte[] encKey, byte[] macKey, byte[] kekKey, int diversification) {
		this(encKey, macKey, kekKey);
		this.diversification = diversification;
	}

	public void diversify(byte[] initialize_update_response) {
		// Caller must assure that this only gets called ONCE after initialize update!
		if (diversified) {
			throw new RuntimeException("Already diversified keys!");
		}
		
		if (diversification == NONE) {
			throw new RuntimeException("No diversification required but diversify() called!");
		}

		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			byte[] data = new byte[16];
			for (int i = 0; i < 3; i++) {

				// shift around and fill initialize update data as required.
				if (diversification == VISA2) {
					fillVisa(data, initialize_update_response, i);
				} else if (diversification == EMV) {
					fillEmv(data, initialize_update_response, i);
				}

				// Encrypt with current master key
				cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(GPUtils.getKey(keys[i], 24) , "DESede"));

				// Replace the key
				keys[i] = cipher.doFinal(data);
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

	private void fillVisa(byte[] data, byte[] init_update_response, int key) {
		// key is 0 based in input
		key++;
		System.arraycopy(init_update_response, 0, data, 0, 2);
		System.arraycopy(init_update_response, 4, data, 2, 4);
		data[6] = (byte) 0xF0;
		data[7] = (byte) key;
		System.arraycopy(init_update_response, 0, data, 8, 2);
		System.arraycopy(init_update_response, 4, data, 10, 4);
		data[14] = (byte) 0x0F;
		data[15] = (byte) key;
	}

	private void fillEmv(byte[] data, byte[] init_update_response, int key) {
		// input key is 0 based
		key++;
		// 6 rightmost bytes of init update response (which is 10 bytes)
		System.arraycopy(init_update_response, 4, data, 0, 6);
		data[6] = (byte) 0xF0;
		data[7] = (byte) key;
		System.arraycopy(init_update_response, 4, data, 8, 6);
		data[14] = (byte) 0x0F;
		data[15] = (byte) key;
	}

	@Override
	public String toString() {
		return new String("\nKeys:\nENC: " + GPUtils.byteArrayToString(keys[0])  + "\nMAC: " + GPUtils.byteArrayToString(keys[1]) + "\nKEK: " + GPUtils.byteArrayToString(keys[2]) + "\n");
	}

}