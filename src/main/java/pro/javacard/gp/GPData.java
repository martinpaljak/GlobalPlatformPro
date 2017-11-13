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

import apdu4j.HexUtils;
import com.payneteasy.tlv.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.GPKey.Type;

import javax.smartcardio.CardException;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

// Various constants from GP specification and other sources
// Methods to pretty-print those structures and constants.
public final class GPData {
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
    // Default test key TODO: provide getters for arrays, this class should be kept public
    static final byte[] defaultKeyBytes = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
    static final GPKey defaultKey = new GPKey(defaultKeyBytes, Type.DES3);
    // Default ISD AID-s
    static final byte[] defaultISDBytes = HexUtils.hex2bin("A000000151000000");
    final static Logger logger = LoggerFactory.getLogger(GPData.class);
    static final Map<Integer, String> sw = new HashMap<>();

    static {
        // Some generics.
        sw.put(0x6400, "No specific diagnosis"); // Table 11-10
        sw.put(0x6700, "Wrong length (Lc)"); // Table 11-10
        sw.put(0x6D00, "Invalid INStruction"); // Table 11-10
        sw.put(0x6E00, "Invalid CLAss"); // Table 11-10

        sw.put(0x6283, "Card Life Cycle State is CARD_LOCKED"); // Table 11-83: SELECT Warning Condition

        sw.put(0x6581, "Memory failure"); // 2.3 Table 11-26: DELETE Error Conditions

        sw.put(0x6882, "Secure messaging not supported");  // 2.3 Table 11-63

        sw.put(0x6982, "Security status not satisfied");  // 2.3 Table 11-78
        sw.put(0x6985, "Conditions of use not satisfied");  // 2.3 Table 11-78

        sw.put(0x6A80, "Wrong data/incorrect values in data"); // Table 11-78
        sw.put(0x6A81, "Function not supported e.g. card Life Cycle State is CARD_LOCKED"); // 2.3 Table 11-63
        sw.put(0x6A82, "Application/file not found"); // 2.3 Table 11-26: DELETE Error Conditions
        sw.put(0x6A84, "Not enough memory space"); // 2.3 Table 11-15
        sw.put(0x6A86, "Incorrect P1/P2"); // 2.3 Table 11-15
        sw.put(0x6A88, "Referenced data not found");  // 2.3 Table 11-78
    }

    @Deprecated
    public static IBerTlvLogger getLoggerInstance() {
        return new IBerTlvLogger() {
            @Override
            public boolean isDebugEnabled() {
                return true;
            }

            @Override
            public void debug(String s, Object... objects) {
                logger.trace(s, objects);
            }
        };
    }

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
            return "Extended Format";

        return "UNKNOWN";
    }

    // Print the key template
    public static void pretty_print_key_template(List<GPKey> list, PrintStream out) {
        boolean factory_keys = false;
        out.flush();
        for (GPKey k : list) {
            out.println("VER:" + k.getVersion() + " ID:" + k.getID() + " TYPE:" + k.getType() + " LEN:" + k.getLength());
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
    public static List<GPKey> get_key_template_list(byte[] data) throws GPException {
        List<GPKey> r = new ArrayList<>();

        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(data);
        BerTlvLogger.log("    ", tlvs, GPData.getLoggerInstance());

        BerTlv keys = tlvs.find(new BerTag(0xE0));
        if (keys != null && keys.isConstructed()) {
            for (BerTlv key : keys.findAll(new BerTag(0xC0))) {
                byte[] tmpl = key.getBytesValue();
                if (tmpl.length < 4) {
                    throw new GPDataException("Key info template shorter than 4 bytes", tmpl);
                }
                int id = tmpl[0] & 0xFF;
                int version = tmpl[1] & 0xFF;
                int type = tmpl[2] & 0xFF;
                int length = tmpl[3] & 0xFF;
                if (type == 0xFF) {
                    // TODO
                    throw new GPDataException("Extended key template not yet supported", tmpl);
                }
                r.add(new GPKey(version, id, length, type));
            }
        }
        return r;
    }

    // GP 2.1.1: F.2 Table F-1
    // Tag 66 with nested 73
    public static void pretty_print_card_data(byte[] data) {
        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(data);
        BerTlvLogger.log("    ", tlvs, GPData.getLoggerInstance());

        BerTlv cd = tlvs.find(new BerTag(0x66));
        if (cd != null && cd.isConstructed()) {
            BerTlv isdd = tlvs.find(new BerTag(0x73));
            if (isdd != null) {
                // Loop all sub-values
                for (BerTlv vt : isdd.getValues()) {
                    BerTlv ot = vt.find(new BerTag(0x06));
                    if (ot != null) {
                        String oid = oid2string(ot.getBytesValue());
                        System.out.println("Tag " + new BigInteger(1, vt.getTag().bytes).toString(16) + ": " + oid);

                        if (oid.equals("1.2.840.114283.1")) {
                            System.out.println("-> Global Platform card");
                        }
                        if (oid.startsWith("1.2.840.114283.2")) {
                            String[] p = oid.substring("1.2.840.114283.2.".length()).split("\\.");
                            System.out.println("-> GP Version: " + String.join(".", p));
                        }

                        if (oid.startsWith("1.2.840.114283.4")) {
                            String[] p = oid.substring("1.2.840.114283.4.".length()).split("\\.");
                            if (p.length == 2) {
                                System.out.println("-> GP SCP0" + p[0] + " i=" + String.format("%02x", Integer.valueOf(p[1])));
                            } else {
                                if (oid.equals("1.2.840.114283.4.0")) {
                                    System.out.println("-> GP SCP80 i=00");
                                }
                            }
                        }
                    }
                }
            }
        } else {
            System.out.println("No Card Data");
        }
    }

    public static void pretty_print_cplc(byte[] data, PrintStream out) {
        if (data == null) {
            out.println("NO CPLC");
            return;
        }
        CPLC cplc = CPLC.fromBytes(data);
        out.println(cplc);
    }

    // TODO public for debuggin purposes
    public static void print_card_info(GlobalPlatform gp) throws CardException, GPException {
        // Print CPLC
        pretty_print_cplc(gp.fetchCPLC(), System.out);

        //
        gp.dumpCardProperties(System.out);
        // Print CardData
        System.out.println("***** CARD DATA");
        byte[] card_data = gp.fetchCardData();
        pretty_print_card_data(card_data);
        // Print Key Info Template
        System.out.println("***** KEY INFO");
        pretty_print_key_template(gp.getKeyInfoTemplate(), System.out);
    }

    public static String sw2str(int sw) {
        String msg = GPData.sw.get(sw);
        if (msg == null)
            return String.format("0x%04X", sw);
        return String.format("0x%04X (%s)", sw, msg);
    }

    public static String oid2string(byte[] oid) {
        try {
            // Prepend 0x06 tag, if not present
            // XXX: if ber-tlv allows to fetch constructed data, this is not needed
            if (oid[0] != 0x06) {
                oid = GPUtils.concatenate(new byte[]{0x06, (byte) oid.length}, oid);
            }
            ASN1ObjectIdentifier realoid = (ASN1ObjectIdentifier) ASN1ObjectIdentifier.fromByteArray(oid);
            if (realoid == null)
                throw new IllegalArgumentException("Could not parse OID from " + HexUtils.bin2hex(oid));
            return realoid.toString();
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not handle " + HexUtils.bin2hex(oid));
        }
    }

    public static GlobalPlatform.GPSpec oid2version(byte[] bytes) throws GPDataException {
        String oid = oid2string(bytes);
        if (oid.equals("1.2.840.114283.2.2.1.1")) {
            return GlobalPlatform.GPSpec.GP211;
        } else if (oid.equals("1.2.840.114283.2.2.2")) {
            return GlobalPlatform.GPSpec.GP22;
        } else if (oid.equals("1.2.840.114283.2.2.2.1")) {
            return GlobalPlatform.GPSpec.GP22; // No need to make a difference
        } else {
            throw new GPDataException("Unknown GP version OID: " + oid, bytes);
        }
    }

    public static final class CPLC {

        private HashMap<Field, byte[]> values = null;

        ;

        private CPLC(byte[] data) {
            // prepended by tag 0x9F7F
            short offset = 3;
            values = new HashMap<>();
            values.put(Field.ICFabricator, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICType, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.OperatingSystemID, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.OperatingSystemReleaseDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.OperatingSystemReleaseLevel, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICFabricationDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICSerialNumber, Arrays.copyOfRange(data, offset, offset + 4));
            offset += 4;
            values.put(Field.ICBatchIdentifier, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICModuleFabricator, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICModulePackagingDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICCManufacturer, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICEmbeddingDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPrePersonalizer, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPrePersonalizationEquipmentDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPrePersonalizationEquipmentID, Arrays.copyOfRange(data, offset, offset + 4));
            offset += 4;
            values.put(Field.ICPersonalizer, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPersonalizationDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPersonalizationEquipmentID, Arrays.copyOfRange(data, offset, offset + 4));
            offset += 4;
        }

        public static CPLC fromBytes(byte[] data) {
            if (data == null || data.length < 3 || data[2] != 0x2A)
                throw new IllegalArgumentException("CPLC MUST be 0x2A bytes long");
            return new CPLC(data);
        }

        public byte[] get(Field f) {
            return values.get(f);
        }

        public String toString() {
            return Arrays.asList(Field.values()).stream().map(i -> i.toString() + "=" + HexUtils.bin2hex(values.get(i))).collect(Collectors.joining(", ", "[CPLC ", "]"));
        }

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
        }
    }
}
