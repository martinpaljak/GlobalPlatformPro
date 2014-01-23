package openkms.gpj;

import java.io.IOException;
import java.util.Arrays;

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

	// GP 2.1.1 9.3.3.1
	public static void pretty_print_keys(byte[] data, short offset) {
		System.out.flush();
		offset = TLVUtils.skip_tag_or_throw(data, offset, (byte) 0xe0);
		offset = TLVUtils.skipLength(data, offset);

		while (offset < data.length) {
			offset = TLVUtils.skipTag(data, offset, (byte) 0xC0);
			int component_len = offset + TLVUtils.get_length(data, offset);
			offset = TLVUtils.skipLength(data, offset);

			System.out.println("Key ID: " + Integer.toHexString(TLVUtils.get_byte_value(data, offset)));
			offset++;
			System.out.println("Key Version: " + Integer.toHexString(TLVUtils.get_byte_value(data, offset)));
			offset++;
			while (offset < component_len) {
				System.out.println(" - type: " + get_key_type_coding_string(TLVUtils.get_byte_value(data, offset)));
				offset++;
				System.out.println(" - length: " + TLVUtils.get_byte_value(data, offset));
				offset++;
			}

		}
	}

	// GP 2.1.1: F.2 Table F-1
	public static void pretty_print_card_data(byte[] data) throws IOException {
		short offset = 0;
		offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x66);
		offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x73);
		while (offset < data.length) {
			int tag = TLVUtils.getTLVTag(data, offset);
			if (tag == 0x06) {
				System.out.println("OID: " + ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVAsBytes(data, offset)));
			} else if (tag == 0x60) {
				System.out.println("GlobalPlatform " + gp_version_from_tlv(data, offset));
			} else if (tag == 0x63) {
				System.out.println("TAG3: " + ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)));
			} else if (tag == 0x64) {
				System.out.println("TAG4: " + ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)));
			} else if (tag == 0x65) {
				System.out.println("TAG5: " + ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)));
			} else if (tag == 0x66) {
				System.out.println("TAG6: " + ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)));
			} else {
				System.out.println("Unknown tag: " + Integer.toHexString(tag));
			}
			offset = TLVUtils.skipAnyTag(data, offset);
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

	public static void get_global_platform_version(byte[] data) {
		short offset = 0;
		offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x66);
		offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x73);
		offset = TLVUtils.findTag(data, offset, (byte) 0x60);
	}


	public static boolean want_emv(byte[] cplc) {
		// G&D?
		if (cplc[7] == 0x16 && cplc[8] == 0x71)
			return true;
		return false;
	}
	private static String bytesAsHex(byte[] data, short offset, int len) {
		return LoggingCardTerminal.encodeHexString(Arrays.copyOfRange(data, offset, len));
	}
	public static void print_cplc_data(byte [] data) {
		if (data.length < 3 || data[2] != 0x2A)
			throw new IllegalArgumentException("CPLC must be 0x2A bytes long");
		short offset = 3;
		//offset = TLVUtils.skipTag(data, offset, (short)0x9F7F);
		System.out.println("IC Fabricator: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Type: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("Operating System ID: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("Operating System release date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("Operating System release level: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Fabrication Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Serial Number: " + bytesAsHex(data, offset, offset + 4)); offset += 4;
		System.out.println("IC Batch Identifier: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Module Fabricator: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Module Packaging Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("ICC Manufacturer: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Embedding Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Pre-Personalizer: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Pre-Perso. Equipment Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Pre-Perso. Equipment ID: " + bytesAsHex(data, offset, offset + 4)); offset += 4;
		System.out.println("IC Personalizer: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Personalization Date: " + bytesAsHex(data, offset, offset + 2)); offset += 2;
		System.out.println("IC Perso. Equipment ID: " + bytesAsHex(data, offset, offset + 4));	 offset += 4;
	}

}
