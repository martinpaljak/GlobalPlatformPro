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

import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import javax.smartcardio.CardException;

import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;

import com.google.common.collect.Lists;

import apdu4j.HexUtils;
import pro.javacard.gp.GPKeySet.GPKey;
import pro.javacard.gp.GPKeySet.GPKey.Type;
import pro.javacard.gp.GlobalPlatform.GPSpec;

public final class GPData {
	public static final byte[] defaultKeyBytes = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };
	public static final GPKey defaultKey = new GPKey(defaultKeyBytes, Type.DES3);

	// SD states
	public static final byte readyStatus = 0x1;
	public static final byte initializedStatus = 0x7;
	public static final byte securedStatus = 0xF;
	public static final byte lockedStatus = 0x7F;
	public static final byte terminatedStatus = (byte) 0xFF;

	// See GP 2.1.1 Table 9-7: Application Privileges
	@Deprecated
	public static final byte defaultSelectedPriv = 0x04;
	@Deprecated
	public static final byte cardLockPriv = 0x10;
	@Deprecated
	public static final byte cardTerminatePriv = 0x08;
	@Deprecated
	public static final byte securityDomainPriv = (byte) 0x80;

	// TODO GP 2.2.1 11.1.2


	public enum KeyType {
		// ID is as used in diversification/derivation
		// That is - one based.
		ENC(1), MAC(2), KEK(3), RMAC(4);

		private final int value;

		private KeyType(int value) {
			this.value = value;
		}

		public byte getValue() {
			return (byte) (value & 0xFF);
		}
	};

	// GP 2.1.1 9.1.6
	// GP 2.2.1 11.1.8
	public static String get_key_type_coding_string(int type) {
		if ((0x00 <= type) && (type <= 0x7f))
			return "Reserved for private use";
		// symmetric
		if (0x80 == type)
			return "DES - mode (ECB/CBC) implicitly known";
		if (0x81 == type)
			return "Reserved (Triple DES)";
		if (0x82 == type)
			return "Triple DES in CBC mode";
		if (0x83 == type)
			return "DES in ECB mode";
		if (0x84 == type)
			return "DES in CBC mode";
		if (0x85 == type)
			return "Pre-Shared Key for Transport Layer Security";
		if (0x88 == type)
			return "AES (16, 24, or 32 long keys)";
		if (0x90 == type)
			return "HMAC-SHA1 - length of HMAC is implicitly known";
		if (0x91 == type)
			return "MAC-SHA1-160 - length of HMAC is 160 bits";
		if (type == 0x86 || type == 0x87 || ((0x89 <= type) && (type <= 0x8F)) || ((0x92 <= type) && (type <= 0x9F)))
			return "RFU (asymmetric algorithms)";
		// asymmetric
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
			return "Extened Format";

		return "UNKNOWN";
	}

	// Print the key template
	public static void pretty_print_key_template(List<GPKeySet.GPKey> list, PrintStream out) {
		boolean factory_keys = false;
		out.flush();
		for (GPKey k: list) {
			out.println("VER:" + k.getVersion() + " ID:" + k.getID() + " TYPE:"+ k.getType() + " LEN:" + k.getLength());
			if (k.getVersion() == 0x00 || k.getVersion() == 0xFF)
				factory_keys = true;
		}
		if (factory_keys) {
			out.println("Key version suggests factory keys");
		}
		out.flush();
	}

	// GP 2.1.1 9.3.3.1
	// GP 2.2.1 11.1.8
	public static List<GPKeySet.GPKey> get_key_template_list(byte[] data) throws GPException {
		List<GPKey> r = new ArrayList<>();

		try (ASN1InputStream ais = new ASN1InputStream(data)) {
			while (ais.available() > 0) {
				ASN1ApplicationSpecific keys = (DERApplicationSpecific)ais.readObject();
				// System.out.println(ASN1Dump.dumpAsString(keys, true));

				ASN1Sequence seq = (ASN1Sequence) keys.getObject(BERTags.SEQUENCE);
				for (ASN1Encodable p: Lists.newArrayList(seq.iterator())) {
					ASN1ApplicationSpecific key = (DERApplicationSpecific) p.toASN1Primitive();
					byte [] tmpl = key.getContents();
					if (tmpl.length < 4) {
						throw new GPDataException("Key info template shorter than 4 bytes", tmpl);
					}
					int id = tmpl[0] & 0xFF;
					int version = tmpl[1] & 0xFF;
					int type = tmpl[2] & 0xFF;
					int length = tmpl[3] & 0xFF;
					if (type == 0xFF) {
						throw new GPDataException("Extended key template not yet supported", tmpl);
					}
					r.add(new GPKey(version, id, length, type));
				}
			}
		} catch (IOException | ClassCastException e) {
			throw new GPDataException("Could not parse key template: " + e.getMessage(), e);
		}
		return r;
	}

	public static GPSpec get_version_from_card_data(byte[] data) throws GPException {
		try (ASN1InputStream ais = new ASN1InputStream(data)) {
			if (ais.available() > 0) {
				// Read card recognition data
				DERApplicationSpecific card_data = (DERApplicationSpecific) ais.readObject();
				ASN1Sequence seq = (ASN1Sequence) card_data.getObject(BERTags.SEQUENCE);
				for (ASN1Encodable p: Lists.newArrayList(seq.iterator())) {
					if (p instanceof ASN1ObjectIdentifier) {
						ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) p;
						// Must be fixed
						if (!oid.toString().equalsIgnoreCase("1.2.840.114283.1")) {
							throw new GPDataException("Invalid CardRecognitionData: " + oid.toString());
						}
					} else if (p instanceof DERApplicationSpecific) {
						DERApplicationSpecific tag = (DERApplicationSpecific) p;
						int n = tag.getApplicationTag();
						if (n == 0) {
							// Version
							String oid = ASN1ObjectIdentifier.getInstance(tag.getObject()).toString();

							if (oid.equalsIgnoreCase("1.2.840.114283.2.2.1.1")) {
								return GPSpec.GP211;
							} else if (oid.equalsIgnoreCase("1.2.840.114283.2.2.2")) {
								return GPSpec.GP22;
							} else if (oid.equals("1.2.840.114283.2.2.2.1")) {
								return GPSpec.GP22; // TODO: no need to differentiate currently
							} else {
								throw new GPDataException("Invalid GP version OID: " + oid);
							}
						}
					} else {
						throw new GPDataException("Invalid type in card data", p.toASN1Primitive().getEncoded());
					}
				}
			}
		} catch (IOException | ClassCastException e) {
			throw new GPDataException("Invalid data: " + e.getMessage());
		}
		// Default to GP211
		return GPSpec.GP211;
	}


	// GP 2.1.1: F.2 Table F-1
	public static void pretty_print_card_data(byte[] data, PrintStream out) {
		if (data == null) {
			out.println("NO CARD DATA");
			return;
		}
		try {
			int offset = 0;
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

	static String gp_version_from_tlv(byte[] data, int offset) {
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

	static String gp_scp_version_from_tlv(byte[] data, int offset) {
		try {
			String oid;
			oid = ASN1ObjectIdentifier.fromByteArray(TLVUtils.getTLVValueAsBytes(data, offset)).toString();
			if (oid.startsWith("1.2.840.114283.4")) {
				String[] p = oid.substring("1.2.840.114283.4.".length()).split("\\.");
				return "SCP_0" +p[0] + "_" + String.format("%02x",Integer.valueOf(p[1]));
			} else {
				return "unknown";
			}
		} catch (IOException e) {
			return "error";
		}
	}

	public static void get_global_platform_version(byte[] data) {
		int offset = 0;
		offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x66);
		offset = TLVUtils.skipTagAndLength(data, offset, (byte) 0x73);
		offset = TLVUtils.findTag(data, offset, (byte) 0x60);
	}

	public static void pretty_print_cplc(byte [] data, PrintStream out) {
		if (data == null) {
			out.println("NO CPLC");
			return;
		}
		CPLC cplc = new CPLC(data);
		out.println(cplc);
	}


	// TODO public for debuggin purposes
	public static void print_card_info(GlobalPlatform gp) throws CardException, GPException {
		// Print CPLC
		pretty_print_cplc(gp.getCPLC(), System.out);
		// Requires GP?
		// Print CardData
		System.out.println("***** CARD DATA");
		byte [] card_data = gp.fetchCardData();
		pretty_print_card_data(card_data, System.out);
		// Print Key Info Template
		System.out.println("***** KEY INFO");
		pretty_print_key_template(gp.getKeyInfoTemplate(), System.out);
	}


	public static final class CPLC {

		public enum Field {
			ICFabricator,
			ICType,
			OperatingSystemID,
			OperatingSystemReleaseDate,
			OperatingSystemReleaseLevel,
			ICFabricationDate,
			ICSerialNumber,
			ICBatchIdentifier,
			ICModuleFabricator,
			ICModulePackagingDate,
			ICCManufacturer,
			ICEmbeddingDate,
			ICPrePersonalizer,
			ICPrePersonalizationEquipmentDate,
			ICPrePersonalizationEquipmentID,
			ICPersonalizer,
			ICPersonalizationDate,
			ICPersonalizationEquipmentID
		};
		private HashMap<Field, byte[]> values = null;

		public CPLC(byte [] data) {
			if (data == null || data.length < 3 || data[2] != 0x2A)
				throw new IllegalArgumentException("CPLC must be 0x2A bytes long");
			//offset = TLVUtils.skipTag(data, offset, (short)0x9F7F);
			short offset = 3;
			values = new HashMap<>();
			values.put(Field.ICFabricator, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICType, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.OperatingSystemID, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.OperatingSystemReleaseDate, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.OperatingSystemReleaseLevel, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICFabricationDate, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICSerialNumber, Arrays.copyOfRange(data, offset, offset + 4)); offset += 4;
			values.put(Field.ICBatchIdentifier, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICModuleFabricator, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICModulePackagingDate, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICCManufacturer, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICEmbeddingDate, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICPrePersonalizer, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICPrePersonalizationEquipmentDate, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICPrePersonalizationEquipmentID, Arrays.copyOfRange(data, offset, offset + 4)); offset += 4;
			values.put(Field.ICPersonalizer, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICPersonalizationDate, Arrays.copyOfRange(data, offset, offset + 2)); offset += 2;
			values.put(Field.ICPersonalizationEquipmentID, Arrays.copyOfRange(data, offset, offset + 4)); offset += 4;
		}

		public String toString() {
			String s = "Card CPLC:";
			for (Field f: Field.values()) {
				s += "\n" + f.name() + ": " + HexUtils.bin2hex(values.get(f));
			}
			return s;
		}
	}

	public static void main(String[] args) throws Exception {
		get_version_from_card_data(HexUtils.hex2bin("734A06072A864886FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A864886FC6B040215650B06092B8510864864020103660C060A2B060104012A026E0102"));
	}
}
