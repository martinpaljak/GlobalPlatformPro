package openkms.gpj;

import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import openkms.gpj.KeySet.Key;
import openkms.gpj.KeySet.KeyDiversification;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class GlobalPlatformData {

	// GP 2.1.1 9.1.6
	public static String get_key_type_coding_string(int type) {
		if ((0x00 <= type) && (type <= 0x7f))
			return "Reserved for private use";
		if (0x80 == type)
			return "DES - mode (ECB/CBC) implicitly known";
		if ((0x81 <= type) && (type <= 0x9F))
			return "RFU (symmetric algorithms)";
		if (0xA0 == type)
			return "RSA Public Key - public exponent e component (clear text)";
		if (0xA1 == type)
			return "RSA Public Key - modulus N component (clear text)";
		if (0xA2 == type)
			return "RSA Private Key - modulus N component";
		if (0xA3 == type)
			return "RSA Private Key - private exponent d component";
		if (0xA4 == type)
			return "RSA Private Key - Chinese Remainder P component";
		if (0xA5 == type)
			return "RSA Private Key - Chinese Remainder Q component";
		if (0xA6 == type)
			return "RSA Private Key - Chinese Remainder PQ component";
		if (0xA7 == type)
			return "RSA Private Key - Chinese Remainder DP1 component";
		if (0xA8 == type)
			return "RSA Private Key - Chinese Remainder DQ1 component";
		if ((0xA9 <= type) && (type <= 0xFE))
			return "RFU (asymmetric algorithms)";
		if (0xFF == type)
			return "Not Available";

		return "UNKNOWN";
	}


	// Print the key template
	public static void pretty_print_key_template(List<KeySet.Key> list, PrintStream out) {
		boolean factory_keys = false;
		out.flush();
		for (Key k: list) {
			out.println("Key ID:" + k.getID() + " VER:" + k.getVersion() + " LEN:" + k.getLength());
			if (k.getVersion() == 0x00|| k.getVersion() == 0xFF)
				factory_keys = true;
		}
		if (factory_keys)
			out.println("Key version suggests factory keys");
		out.flush();
	}

	// GP 2.1.1 9.3.3.1
	public static List<KeySet.Key> get_key_template_list(byte[] data, short offset) {

		// Return empty list if no data from card.
		// FIXME: not really a clean solution
		if (data == null)
			return new ArrayList<Key>();

		offset = TLVUtils.skip_tag_or_throw(data, offset, (byte) 0xe0);
		offset = TLVUtils.skipLength(data, offset);

		ArrayList<KeySet.Key> list = new ArrayList<Key>();
		while (offset < data.length) {
			offset = TLVUtils.skipTag(data, offset, (byte) 0xC0);
			int component_len = offset + TLVUtils.get_length(data, offset);
			offset = TLVUtils.skipLength(data, offset);

			int id = TLVUtils.get_byte_value(data, offset);
			offset++;
			int version = TLVUtils.get_byte_value(data, offset);
			offset++;
			while (offset < component_len) {
				int type = TLVUtils.get_byte_value(data, offset);
				offset++;
				int length = TLVUtils.get_byte_value(data, offset);
				offset++;
				list.add(new Key(version, id, length, type));
				break; // FIXME:
			}
		}
		return list;
	}


	// GP 2.1.1: F.2 Table F-1
	public static void pretty_print_card_data(byte[] data, PrintStream out) {
		if (data == null) {
			out.println("NO CARD DATA");
			return;
		}
		try {
			short offset = 0;
			offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x66);
			offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x73);
			while (offset < data.length) {
				int tag = TLVUtils.getTLVTag(data, offset);
				if (tag == 0x06) {
					String oid = ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVAsBytes(data, offset)).toString();
					if (oid.equals("1.2.840.114283.1"))
						out.println("GlobalPlatform card");
				} else if (tag == 0x60) {
					out.println("Version: " + gp_version_from_tlv(data, offset));
				} else if (tag == 0x63) {
					out.println("TAG3: " + ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)));
				} else if (tag == 0x64) {
					out.println("SCP version: " + gp_scp_version_from_tlv(data, offset));
				} else if (tag == 0x65) {
					out.println("TAG5: " + ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)));
				} else if (tag == 0x66) {
					out.println("TAG6: " + ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)));
				} else {
					out.println("Unknown tag: " + Integer.toHexString(tag));
				}
				offset = TLVUtils.skipAnyTag(data, offset);
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static String gp_version_from_tlv(byte[] data, short offset) {
		try {
			String oid;
			oid = ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)).toString();
			if (oid.startsWith("1.2.840.114283.2")) {
				return oid.substring("1.2.840.114283.2.".length());
			} else {
				return "unknown";
			}
		} catch (IOException e) {
			return "error";
		}
	}

	private static String gp_scp_version_from_tlv(byte[] data, short offset) {
		try {
			String oid;
			oid = ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)).toString();
			if (oid.startsWith("1.2.840.114283.4")) {
				return oid.substring("1.2.840.114283.4.".length());
			} else {
				return "unknown";
			}
		} catch (IOException e) {
			return "error";
		}
	}

	public static void get_global_platform_version(byte[] data) {
		short offset = 0;
		offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x66);
		offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x73);
		offset = TLVUtils.findTag(data, offset, (byte) 0x60);
	}


	public static KeyDiversification suggestDiversification(byte[] cplc) {
		if (cplc != null) {
			// G&D
			if (cplc[7] == 0x16 && cplc[8] == 0x71)
				return KeyDiversification.EMV;
			// TODO: Gemalto
		}
		return KeyDiversification.NONE;
	}


	private static String bytesAsHex(byte[] data, short offset, int len) {
		return LoggingCardTerminal.encodeHexString(Arrays.copyOfRange(data, offset, len));
	}


	public static void pretty_print_cplc(byte [] data, PrintStream out) {
		if (data == null) {
			out.println("NO CPLC");
			return;
		}
		if (data.length < 3 || data[2] != 0x2A)
			throw new IllegalArgumentException("CPLC must be 0x2A bytes long");
		short offset = 3;
		//offset = TLVUtils.skipTag(data, offset, (short)0x9F7F);
		out.println("***** Card CPLC:");
		out.println("IC Fabricator: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Type: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("Operating System ID: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("Operating System release date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("Operating System release level: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Fabrication Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Serial Number: " + bytesAsHex(data, offset, offset + 4)); offset += 4;
		out.println("IC Batch Identifier: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Module Fabricator: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Module Packaging Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("ICC Manufacturer: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Embedding Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Pre-Personalizer: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Pre-Perso. Equipment Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Pre-Perso. Equipment ID: " + bytesAsHex(data, offset, offset + 4)); offset += 4;
		out.println("IC Personalizer: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Personalization Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		out.println("IC Perso. Equipment ID: " + bytesAsHex(data, offset, offset + 4));	 offset += 4;
	}

}
