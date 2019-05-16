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

import apdu4j.APDUBIBO;
import apdu4j.CommandAPDU;
import apdu4j.HexUtils;
import apdu4j.ResponseAPDU;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

import static pro.javacard.gp.GPSession.CLA_GP;

// Various constants from GP specification and other sources
// Methods to pretty-print those structures and constants.
public final class GPData {
    private static final Logger logger = LoggerFactory.getLogger(GPData.class);

    // SD states
    public static final byte readyStatus = 0x1;
    public static final byte initializedStatus = 0x7;
    public static final byte securedStatus = 0xF;
    public static final byte lockedStatus = 0x7F;
    public static final byte terminatedStatus = (byte) 0xFF;

    // Default ISD AID-s
    static final byte[] defaultISDBytes = HexUtils.hex2bin("A000000151000000");
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

    // GP 2.1.1: F.2 Table F-1
    // Tag 66 with nested 73
    public static void pretty_print_card_data(byte[] data) {
        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(data);
        GPUtils.trace_tlv(data, logger);

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
                        if (oid.startsWith("1.3.6.1.4.1.42.2.110.1")) {
                            String p = oid.substring("1.3.6.1.4.1.42.2.110.1.".length());
                            if (p.length() == 1) {
                                System.out.println("-> JavaCard v" + p);
                            }
                        }
                    }
                }
            }
        } else {
            System.out.println("No Card Data");
        }
    }

    // GPV 2.2 AmdE 6.1
    public static void pretty_print_card_capabilities(byte[] data) throws GPDataException {
        // BUGFIX: exist cards that return nested 0x67 tag with GET DATA with GP CLA
        if (data[0] == 0x67 && data[2] == 0x67) {
            logger.warn("Bogus data detected, fixing double tag");
            data = Arrays.copyOfRange(data, 2, data.length);
        }
        // END BUGFIX

        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(data);
        GPUtils.trace_tlv(data, logger);
        if (tlvs != null) {
            BerTlv caps = tlvs.find(new BerTag(0x67));
            if (caps != null) {
                for (BerTlv v : caps.getValues()) {
                    BerTlv t = v.find(new BerTag(0xA0));
                    if (t != null) {
                        BerTlv scp = t.find(new BerTag(0x80));
                        if (scp != null) {
                            System.out.format("Supports: SCP%02X", scp.getIntValue());
                            BerTlv is = t.find(new BerTag(0x81));
                            if (is != null) {
                                byte[] isv = is.getBytesValue();
                                for (int i = 0; i < isv.length; i++) {
                                    System.out.format(" i=%02X", isv[i]);
                                }
                            }
                            BerTlv keylens = t.find(new BerTag(0x82));
                            if (keylens != null) {
                                System.out.print(" with");
                                if ((keylens.getIntValue() & 0x01) == 0x01) {
                                    System.out.print(" AES-128");
                                }
                                if ((keylens.getIntValue() & 0x02) == 0x02) {
                                    System.out.print(" AES-196");
                                }
                                if ((keylens.getIntValue() & 0x04) == 0x04) {
                                    System.out.print(" AES-256");
                                }
                            }
                        }
                        System.out.println();
                        continue;
                    }
                    t = v.find(new BerTag(0x81));
                    if (t != null) {
                        System.out.println("Supported DOM privileges: " + GPRegistryEntry.Privileges.fromBytes(t.getBytesValue()));
                        continue;
                    }
                    t = v.find(new BerTag(0x82));
                    if (t != null) {
                        System.out.println("Supported APP privileges: " + GPRegistryEntry.Privileges.fromBytes(t.getBytesValue()));
                        continue;
                    }
                    t = v.find(new BerTag(0x83));
                    if (t != null) {
                        System.out.println("Supported LFDB hash: " + HexUtils.bin2hex(t.getBytesValue()));
                        continue;
                    }
                    t = v.find(new BerTag(0x85));
                    if (t != null) { // TODO: parse
                        System.out.println("Supported Token Verification ciphers: " + HexUtils.bin2hex(t.getBytesValue()));
                        continue;
                    }
                    t = v.find(new BerTag(0x86));
                    if (t != null) {
                        System.out.println("Supported Receipt Generation ciphers: " + HexUtils.bin2hex(t.getBytesValue()));
                        continue;
                    }
                    t = v.find(new BerTag(0x87));
                    if (t != null) {
                        System.out.println("Supported DAP Verification ciphers: " + HexUtils.bin2hex(t.getBytesValue()));
                        continue;
                    }
                    t = v.find(new BerTag(0x88));
                    if (t != null) {
                        System.out.println("Supported ECC Key Parameters: " + HexUtils.bin2hex(t.getBytesValue()));
                        continue;
                    }
                }
            }
        }
    }


    // NB! This assumes a selected (I)SD!
    public static void dump(APDUBIBO channel) throws IOException, GPException {
        byte[] cplc = fetchCPLC(channel);
        if (cplc != null) {
            System.out.println(GPData.CPLC.fromBytes(cplc).toPrettyString());
        }

        // IIN
        byte[] iin = getData(channel, 0x00, 0x42, "IIN", false);
        if (iin != null) {
            System.out.println("IIN: " + HexUtils.bin2hex(iin));
        }
        // CIN
        byte[] cin = getData(channel, 0x00, 0x45, "CIN", false);
        if (cin != null) {
            System.out.println("CIN: " + HexUtils.bin2hex(cin));
        }
        // FIXME: SSC?
//        BerTlvParser parser = new BerTlvParser();
//        BerTlvs tlvs = parser.parse(resp.getData());
//        BerTlvLogger.log("    ", tlvs, GPData.getLoggerInstance());
//        if (tlvs != null) {
//            BerTlv ssc = tlvs.find(new BerTag(0xC1));
//            if (ssc != null) {
//                out.println(HexUtils.bin2hex(ssc.getBytesValue()));
//            }
//        }
        // Print Card Data
        System.out.println("Card Data: ");
        byte[] cardData = getData(channel, 0x00, 0x66, "Card Data", false);
        if (cardData != null) {
            pretty_print_card_data(cardData);
        }
        // Print Card Capabilities
        System.out.println("Card Capabilities: ");
        byte[] cardCapabilities = getData(channel, 0x00, 0x67, "Card Capabilities", false);
        if (cardCapabilities != null) {
            pretty_print_card_capabilities(cardCapabilities);
        }

        // Print Key Info Template
        byte[] keyInfo = fetchKeyInfoTemplate(channel);
        if (keyInfo != null) {
            GPKeyInfo.print(GPKeyInfo.parseTemplate(keyInfo), System.out);
        }
    }

    // Just to encapsulate tag constants behind meaningful name
    public static byte[] fetchCPLC(APDUBIBO channel) throws IOException {
        return getData(channel, 0x9f, 0x7f, "CPLC", true);
    }

    public static byte[] fetchKeyInfoTemplate(APDUBIBO channel) throws IOException {
        return getData(channel, 0x00, 0xE0, "Key Info Template", false);
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

    public static GPSession.GPSpec oid2version(byte[] bytes) throws GPDataException {
        String oid = oid2string(bytes);
        if (oid.equals("1.2.840.114283.2.2.1.1")) {
            return GPSession.GPSpec.GP211;
        } else if (oid.equals("1.2.840.114283.2.2.2")) {
            return GPSession.GPSpec.GP22;
        } else if (oid.equals("1.2.840.114283.2.2.2.1")) {
            return GPSession.GPSpec.GP22; // No need to make a difference
        } else {
            throw new GPDataException("Unknown GP version OID: " + oid, bytes);
        }
    }

    public static byte[] getData(APDUBIBO channel, int p1, int p2, String name, boolean failsafe) throws IOException {
        logger.trace("GET DATA({})", name);
        ResponseAPDU resp = channel.transmit(new CommandAPDU(CLA_GP, ISO7816.INS_GET_DATA, p1, p2, 256));
        if (failsafe && resp.getSW() != ISO7816.SW_NO_ERROR)
            resp = channel.transmit(new CommandAPDU(0x00, ISO7816.INS_GET_DATA, p1, p2, 256));
        if (resp.getSW() == ISO7816.SW_NO_ERROR) {
            return resp.getData();
        } else if (resp.getSW() == 0x6A88) {
            logger.debug("GET DATA({}): N/A", name);
            return null;
        } else {
            logger.warn("GET DATA({}) not supported", name);
            return null;
        }
    }

    public static final class CPLC {

        private HashMap<Field, byte[]> values = new HashMap<>();

        private CPLC(byte[] data) {
            int offset = 0;
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

        public static CPLC fromBytes(byte[] data) throws GPDataException {
            if (data == null)
                throw new IllegalArgumentException("data is null");
            if (data.length < 0x2A)
                throw new GPDataException(String.format("Input can't be valid CPLC if length is only %02X!", data.length));
            // Remove tag, if present
            if (data[0] == (byte) 0x9f && data[1] == (byte) 0x7f && data[2] == (byte) 0x2A)
                data = Arrays.copyOfRange(data, 3, data.length);
            return new CPLC(data);
        }

        public byte[] get(Field f) {
            return values.get(f);
        }

        public String toString() {
            return Arrays.asList(Field.values()).stream().map(i -> i.toString() + "=" + HexUtils.bin2hex(values.get(i))).collect(Collectors.joining(", ", "[CPLC: ", "]"));
        }

        public String toPrettyString() {
            return Arrays.asList(Field.values()).stream().map(i -> i.toString() + "=" + HexUtils.bin2hex(values.get(i)) + (i.toString().endsWith("Date") ? " (" + toDateFailsafe(values.get(i)) + ")" : "")).collect(Collectors.joining("\n      ", "CPLC: ", "\n"));
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

        public static String toDate(byte[] v) throws GPDataException {
            String sv = HexUtils.bin2hex(v);
            try {
                int y = Integer.parseInt(sv.substring(0, 1));
                int d = Integer.parseInt(sv.substring(1, 4));
                if (d > 366) {
                    throw new GPDataException("Invalid CPLC date format: " + sv);
                }
                // Make 0000 show something meaningful
                if (d == 0) {
                    d = 1;
                }
                GregorianCalendar gc = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
                // FIXME: 2010 is hardcoded.
                gc.set(GregorianCalendar.YEAR, 2010 + y);
                gc.set(GregorianCalendar.DAY_OF_YEAR, d);
                SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd");
                return f.format(gc.getTime());
            } catch (NumberFormatException e) {
                throw new GPDataException("Invalid CPLC date: " + sv, e);
            }
        }

        public static String toDateFailsafe(byte[] v) {
            try {
                return toDate(v);
            } catch (GPDataException e) {
                logger.warn("Invalid CPLC date: " + HexUtils.bin2hex(v));
                return "invalid date format";
            }
        }

        public static byte[] today() {
            return fromDate(new GregorianCalendar());
        }

        public static byte[] fromDate(GregorianCalendar d) {
            return HexUtils.hex2bin(String.format("%d%03d", d.get(GregorianCalendar.YEAR) - 2010, d.get(GregorianCalendar.DAY_OF_YEAR)));
        }
    }
}
