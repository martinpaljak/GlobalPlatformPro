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

import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.data.BitField;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

import static pro.javacard.gp.GPSession.CLA_GP;
import static pro.javacard.gp.data.BitField.byte_mask;

// Various constants from GP specification and other sources
// Methods to pretty-print those structures and constants.
public final class GPData {
    private static final Logger logger = LoggerFactory.getLogger(GPData.class);

    private GPData() {
    }

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

        sw.put(0x6438, "Imported package not available"); // Table 9-14
                                                          // https://docs.oracle.com/javacard/3.0.5/guide/downloading-cap-files-and-creating-applets.htm#JCUGC296

        sw.put(0x6581, "Memory failure"); // 2.3 Table 11-26: DELETE Error Conditions

        sw.put(0x6882, "Secure messaging not supported"); // 2.3 Table 11-63

        sw.put(0x6982, "Security status not satisfied"); // 2.3 Table 11-78
        sw.put(0x6985, "Conditions of use not satisfied"); // 2.3 Table 11-78

        sw.put(0x6999, "Applet selection failed"); // JCRE 4.6.1

        sw.put(0x6A80, "Wrong data/incorrect values in data"); // Table 11-78
        sw.put(0x6A81, "Function not supported e.g. card Life Cycle State is CARD_LOCKED"); // 2.3 Table 11-63
        sw.put(0x6A82, "Application/file not found"); // 2.3 Table 11-26: DELETE Error Conditions
        sw.put(0x6A84, "Not enough memory space"); // 2.3 Table 11-15
        sw.put(0x6A86, "Incorrect P1/P2"); // 2.3 Table 11-15
        sw.put(0x6A88, "Referenced data not found"); // 2.3 Table 11-78
    }

    // GP 2.1.1: F.2 Table F-1
    // Tag 66 with nested 73
    public static void pretty_print_card_data(byte[] data) {
        var tlvs = TLV.parse(data);
        GPUtils.trace_tlv(data, logger);

        var cd = TLV.find(tlvs, Tag.ber(0x66));
        if (cd.isPresent() && cd.get().hasChildren()) {
            var isdd = TLV.find(tlvs, Tag.ber(0x73));
            if (isdd.isPresent()) {
                // Loop all sub-values
                for (TLV vt : isdd.get().children()) {
                    if (vt.tag().equals(Tag.ber(0x06))) {
                        String oid = logAndGetOidFromByteArray(vt.tag().bytes(), vt.value());
                        if (oid.equals("1.2.840.114283.1")) {
                            System.out.println("-> Global Platform card");
                        }
                    } else if (vt.tag().equals(Tag.ber(0x60))) {
                        String oid = logAndGetOidFromByteArray(vt.tag().bytes(),
                                vt.children().get(0).value()); // 6X are constructed tags
                        if (oid.startsWith("1.2.840.114283.2")) {
                            String[] p = oid.substring("1.2.840.114283.2.".length()).split("\\.");
                            System.out.println("-> GP Version: " + String.join(".", p));
                        }
                    } else if (vt.tag().equals(Tag.ber(0x63))) {
                        String oid = logAndGetOidFromByteArray(vt.tag().bytes(),
                                vt.children().get(0).value()); // 6X are constructed tags
                        if (oid.startsWith("1.2.840.114283.3")) {
                            System.out.println(
                                    "-> GP card is uniquely identified by the Issuer Identification Number (IIN) and Card Image Number (CIN)");
                        }
                    } else if (vt.tag().equals(Tag.ber(0x64))) {
                        // Format 1 and Format 2 support
                        for (TLV ot : vt.children()) {
                            byte[] oidBytes = ot.value();
                            String oid = logAndGetOidFromByteArray(ot.tag().bytes(), oidBytes);
                            // This also works with the invalid encoding for SCP80 i=00
                            if (oid.startsWith("1.2.840.114283.4.")) {
                                byte[] scp = Arrays.copyOfRange(oidBytes, oidBytes.length - 2, oidBytes.length);
                                System.out.printf("-> GP %s%n",
                                        GPSecureChannelVersion.valueOf(scp[0] & 0xFF, scp[1] & 0xFF));
                            }
                        }
                    } else if (vt.tag().equals(Tag.ber(0x65))) {
                        // TODO: No format defined yet?
                    } else if (vt.tag().equals(Tag.ber(0x66))) {
                        String oid = logAndGetOidFromByteArray(vt.tag().bytes(),
                                vt.children().get(0).value()); // 6X are constructed tags
                        if (oid.startsWith("1.3.6.1.4.1.42.2.110.1")) {
                            String p = oid.substring("1.3.6.1.4.1.42.2.110.1.".length());
                            if (p.length() == 1) {
                                System.out.println("-> JavaCard v" + p);
                            }
                        }
                    } else if (vt.tag().equals(Tag.ber(0x67))) {
                        // TODO: SCP10 parsing, is it worth it?
                    } else if (vt.tag().equals(Tag.ber(0x68))) {
                        // TODO: SCP10 parsing, is it worth it?
                    }
                }
            }
        } else {
            System.out.println("No Card Data");
        }
    }

    public enum LFDBH {
        SHA1(0x01, "SHA-1"),
        SHA256(0x02, "SHA-256"),
        SHA384(0x03, "SHA-384"),
        SHA512(0x04, "SHA-512");

        final int value;
        final String algo;

        LFDBH(int byteValue, String algo) {
            this.value = byteValue;
            this.algo = algo;
        }

        public static Optional<LFDBH> byValue(int byteValue) {
            return Arrays.stream(values()).filter(e -> e.value == byteValue).findFirst();
        }

        public static Optional<LFDBH> fromString(String s) {
            return Arrays.stream(values()).filter(e -> e.name().equalsIgnoreCase(s)).findFirst();
        }

        public static ArrayList<LFDBH> fromBytes(byte[] v) {
            ArrayList<LFDBH> r = new ArrayList<>();
            for (int i = 0; i < v.length; i++) {
                final int j = i; // TODO: IntStream.range() ?
                r.add(Arrays.stream(values()).filter(e -> e.value == (v[j] & 0xFF)).findFirst()
                        .orElseThrow(() -> new GPDataException("Invalid value", v)));
            }
            return r;
        }

        @Override
        public String toString() {
            return algo;
        }
    }

    // GPC 2.3.1 Table H-9 and Table H-10
    public enum SIGNATURE implements BitField<SIGNATURE> {
        // First byte
        RSA1024_SHA1(byte_mask(0, 0x01)),
        RSAPSS_SHA256(byte_mask(0, 0x02)),
        DES_MAC(byte_mask(0, 0x04)),
        CMAC_AES128(byte_mask(0, 0x08)),
        CMAC_AES192(byte_mask(0, 0x10)),
        CMAC_AES256(byte_mask(0, 0x20)),
        ECCP256_SHA256(byte_mask(0, 0x40)),
        ECCP384_SHA384(byte_mask(0, 0x80)),
        // Second byte
        ECCP512_SHA512(byte_mask(1, 0x01)),
        ECCP521_SHA512(byte_mask(1, 0x02)),
        RFU(new Def.RFU(byte_mask(1, 0xFC)));

        private final BitField.Def def;

        SIGNATURE(BitField.Def def) {
            this.def = def;
        }

        @Override
        public Def def() {
            return def;
        }
    }

    static List<Integer> toUnsignedList(byte[] b) {
        ArrayList<Integer> r = new ArrayList<>();
        for (byte value : b)
            r.add(value & 0xFF);
        return r;
    }

    // GPV 2.2 AmdE 6.1 /
    public static void pretty_print_card_capabilities(byte[] data) throws GPDataException {
        // BUGFIX: exist cards that return nested 0x67 tag with GET DATA with GP CLA
        if (data[0] == 0x67 && data[2] == 0x67) {
            logger.warn("Bogus data detected, fixing double tag");
            data = Arrays.copyOfRange(data, 2, data.length);
        }
        // END BUGFIX

        var tlvs = TLV.parse(data);
        GPUtils.trace_tlv(data, logger);
        var capsOpt = TLV.find(tlvs, Tag.ber(0x67));
        if (capsOpt.isPresent()) {
            for (TLV v : capsOpt.get().children()) {
                var t = v.find(Tag.ber(0xA0));
                if (t != null) {
                    var scp = t.find(Tag.ber(0x80));
                    if (scp != null) {
                        System.out.format("Supports SCP%02X", be2int(scp.value()));
                        var is = t.find(Tag.ber(0x81));
                        if (is != null) {
                            for (byte b : is.value()) {
                                System.out.format(" i=%02X", b);
                            }
                        }
                        var keylens = t.find(Tag.ber(0x82));
                        if (keylens != null) {
                            System.out.print(" with");
                            int keyval = be2int(keylens.value());
                            if ((keyval & 0x01) == 0x01) {
                                System.out.print(" AES-128");
                            }
                            if ((keyval & 0x02) == 0x02) {
                                System.out.print(" AES-196");
                            }
                            if ((keyval & 0x04) == 0x04) {
                                System.out.print(" AES-256");
                            }
                        }
                    }
                    System.out.println();
                    continue;
                }
                t = v.find(Tag.ber(0x81));
                if (t != null) {
                    Set<GPRegistryEntry.Privilege> privs = BitField.parse(GPRegistryEntry.Privilege.class, t.value());
                    System.out.println("Supported DOM privileges: "
                            + privs.stream().map(Enum::toString).collect(Collectors.joining(", ")));
                    continue;
                }
                t = v.find(Tag.ber(0x82));
                if (t != null) {
                    Set<GPRegistryEntry.Privilege> privs = BitField.parse(GPRegistryEntry.Privilege.class, t.value());
                    System.out.println("Supported APP privileges: "
                            + privs.stream().map(Enum::toString).collect(Collectors.joining(", ")));
                    continue;
                }
                t = v.find(Tag.ber(0x83));
                if (t != null) {
                    String hashes = toUnsignedList(t.value()).stream().map(e -> LFDBH.byValue(e).get().toString())
                            .collect(Collectors.joining(", "));
                    System.out.println("Supported LFDB hash: " + hashes);
                    continue;
                }
                t = v.find(Tag.ber(0x85));
                if (t != null) {
                    String ciphers = BitField.parse(SIGNATURE.class, t.value()).stream().map(Enum::toString)
                            .collect(Collectors.joining(", "));
                    System.out.println("Supported Token Verification ciphers: " + ciphers);
                    continue;
                }
                t = v.find(Tag.ber(0x86));
                if (t != null) {
                    String ciphers = BitField.parse(SIGNATURE.class, t.value()).stream().map(Enum::toString)
                            .collect(Collectors.joining(", "));
                    System.out.println("Supported Receipt Generation ciphers: " + ciphers);
                    continue;
                }
                t = v.find(Tag.ber(0x87));
                if (t != null) {
                    String ciphers = BitField.parse(SIGNATURE.class, t.value()).stream().map(Enum::toString)
                            .collect(Collectors.joining(", "));
                    System.out.println("Supported DAP Verification ciphers: " + ciphers);
                    continue;
                }
                t = v.find(Tag.ber(0x88));
                if (t != null) {
                    System.out.println("Supported ECC Key Parameters: " + HexUtils.bin2hex(t.value()));
                    continue;
                }
            }
        }
    }

    // NB! This assumes a selected (I)SD!
    public static void dump(APDUBIBO channel) throws IOException, GPException {
        byte[] cplc = fetchCPLC(channel);
        if (cplc != null) {
            System.out.println(CPLC.fromBytes(cplc).toPrettyString());
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

        // KDD
        byte[] kdd = getData(channel, 0x00, 0xCF, "KDD", false);
        if (kdd != null) {
            System.out.println("KDD: " + HexUtils.bin2hex(kdd));
        }
        // SSC
        byte[] ssc = getData(channel, 0x00, 0xC1, "SSC", false);
        if (ssc != null) {
            System.out.println("SSC: " + HexUtils.bin2hex(ssc));
        }
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
            System.out.println(GPKeyInfo.toString(GPKeyInfo.parseTemplate(keyInfo)));
        }
    }

    // Just to encapsulate tag constants behind meaningful name
    public static byte[] fetchCPLC(APDUBIBO channel) {
        return getData(channel, 0x9f, 0x7f, "CPLC", true);
    }

    public static byte[] fetchKeyInfoTemplate(APDUBIBO channel) {
        return getData(channel, 0x00, 0xE0, "Key Info Template", false);
    }

    public static String sw2str(int sw) {
        String msg = GPData.sw.get(sw);
        if (msg == null)
            return String.format("0x%04X", sw);
        return String.format("0x%04X (%s)", sw, msg);
    }

    public static String oid2string(byte[] oid) {
        logger.trace("Parsing {} as OID", HexUtils.bin2hex(oid));
        // See https://github.com/bcgit/bc-java/issues/1758
        // BC 1.78 and 1.79 were affected.
        // 2A864886FC6B048000 would throw exception instead of returning
        // "1.2.840.114283.4.0" without this
        System.setProperty("org.bouncycastle.asn1.allow_wrong_oid_enc", "true");
        ASN1ObjectIdentifier realoid = ASN1ObjectIdentifier.fromContents(oid);
        System.clearProperty("org.bouncycastle.asn1.allow_wrong_oid_enc");
        if (realoid == null)
            throw new IllegalArgumentException("Could not parse OID from " + HexUtils.bin2hex(oid));
        return realoid.toString();
    }

    private static String logAndGetOidFromByteArray(byte[] tag, byte[] tlv) {
        String oid = oid2string(tlv);
        System.out.println("Tag " + new BigInteger(1, tag).toString(16) + ": " + oid);
        return oid;
    }

    // Big-endian bytes to int (1-4 bytes)
    private static int be2int(byte[] b) {
        int r = 0;
        for (byte v : b)
            r = (r << 8) | (v & 0xFF);
        return r;
    }

    public static String oid2version(byte[] bytes) throws GPDataException {
        String oid = oid2string(bytes);
        return oid.substring("1.2.840.114283.2.".length());
    }

    public static byte[] getData(APDUBIBO channel, int p1, int p2, String name, boolean failsafe) {
        logger.trace("GET DATA({})", name);
        ResponseAPDU resp = channel.transmit(new CommandAPDU(CLA_GP, GPSession.INS_GET_DATA, p1, p2, 256));
        if (failsafe && resp.getSW() != GPSession.SW_NO_ERROR)
            resp = channel.transmit(new CommandAPDU(0x00, GPSession.INS_GET_DATA, p1, p2, 256));
        if (resp.getSW() == GPSession.SW_NO_ERROR) {
            return resp.getData();
        } else if (resp.getSW() == 0x6A88) {
            logger.debug("GET DATA({}): N/A", name);
            return null;
        } else {
            logger.warn("GET DATA({}) not supported", name);
            return null;
        }
    }

}
