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

import apdu4j.core.HexUtils;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// Encapsulates key metadata
public final class GPKeyInfo {
    private static final Logger logger = LoggerFactory.getLogger(GPKeyInfo.class);

    private GPKey type;
    private List<GPKeyInfoElement> elements;
    private int version = 0; // 1..7f
    private int id = -1; // 0..7f
    private int length = -1;
    private int access = -1; // bit field
    private int usage = -1; // bit field

    // Called when parsing KeyInfo template
    public GPKeyInfo(int version, int id, int length, GPKey type) {
        this.version = version;
        this.id = id;
        this.length = length;
        this.type = type;
    }

    public GPKeyInfo(int version, int id, List<GPKeyInfoElement> elements, int access, int usage) {
        this.version = version;
        this.id = id;
        List<GPKeyInfoElement> valid = elements.stream().filter(GPKeyInfoElement::isValid).collect(Collectors.toList());

        if (elements.size() != valid.size()) {
            HashSet<GPKeyInfoElement> unknown = new HashSet<>(elements);
            unknown.removeAll(valid);
            logger.warn("Unknown elements ignored: " + unknown);
        }
        if (valid.size() == 0) {
            throw new IllegalArgumentException("No key elements!");
        } else if (valid.size() == 1) {
            this.length = elements.get(0).keyLength;
            this.type = elements.get(0).key;
        } else {
            // FIXME: reduce here RSA to a single public key
            Optional<GPKeyInfoElement> rsa = valid.stream().filter(e -> e.key == GPKey.RSA_PUB_N).findFirst();
            Optional<GPKeyInfoElement> ecc = valid.stream().filter(e ->
                    (e.key == GPKey.EC_PRIV) || (e.key == GPKey.EC_PUB)).findFirst();
            if (rsa.isPresent()) {
                this.length = rsa.get().keyLength;
                this.type = GPKey.RSA_PUB_N;
            } else if (ecc.isPresent()) {
                // TODO: If ecc, shall we use the CRT parameter on the second element EC_PARAM_REF, to know the exact curve?
                this.length = ecc.get().keyLength;
                GPKey.get(ecc.get().key.getType()).ifPresent(gpKey -> this.type = gpKey);
            } else {
                logger.error("Multiple unsupported elements in key info:  {} ", elements);
                throw new GPDataException("Multiple unsupported elements in key info template");
            }
        }
        this.elements = elements;

        // FIXME: handle them as optionals here
        this.access = access;
        this.usage = usage;
    }


    // GP 2.1.1 9.3.3.1
    // GP 2.2.1 11.3.3.1 and 11.1.8
    public static List<GPKeyInfo> parseTemplate(byte[] data) throws GPException {
        List<GPKeyInfo> r = new ArrayList<>();

        if (data == null || data.length == 0) {
            logger.warn("Template is null or zero length");
            return r;
        }

        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(data);
        GPUtils.trace_tlv(data, logger);

        BerTlv keys = tlvs.find(new BerTag(0xE0));
        if (keys != null && keys.isConstructed()) {
            for (BerTlv key : keys.findAll(new BerTag(0xC0))) {
                final byte[] tmpl = key.getBytesValue();
                if (tmpl.length == 0) {
                    // Fresh SSD with an empty template.
                    logger.info("Key template has zero length (empty). Skipping.");
                    continue;
                }
                if (tmpl.length < 4) {
                    throw new GPDataException("Key info template shorter than 4 bytes", tmpl);
                }
                int offset = 0;
                int id = tmpl[offset++] & 0xFF;
                int version = tmpl[offset++] & 0xFF;

                // Check if extended template
                boolean extended = tmpl[offset] == (byte) 0xFF;

                // With extended, last 4 or 5 bytes are access and usage
                ArrayList<GPKeyInfoElement> elements = new ArrayList<>();
                // Except for some buggy cards, that return extended elements mixed with basic elements.
                for (; offset + (extended ? 4 : 0) < tmpl.length; ) {
                    GPKeyInfoElement element = extended ? GPKeyInfoElement.fromExtendedBytes(tmpl, offset) : new GPKeyInfoElement(tmpl, offset);
                    elements.add(element);
                    logger.trace("Parsed {}", element);
                    offset += element.templateLength;
                }

                if (extended) {
                    // FIXME: Mandatory access and usage
                    logger.warn("Access and Usage not parsed: " + HexUtils.bin2hex(Arrays.copyOfRange(tmpl, offset, tmpl.length)));
                    r.add(new GPKeyInfo(version, id, elements, -1, -1));
                } else {
                    // FIXME: default values in spec
                    r.add(new GPKeyInfo(version, id, elements, -1, -1));
                }
            }
        }
        return r;
    }

    final static Map<Integer, String> keyVersionPurposes;

    static {
        LinkedHashMap<Integer, String> tmp = new LinkedHashMap<>();
        tmp.put(0x70, "Token Verification");
        tmp.put(0x71, "Receipt Generation");
        tmp.put(0x73, "DAP Verification");
        keyVersionPurposes = Collections.unmodifiableMap(tmp);
    }

    private static Optional<String> getPurposeDescription(GPKeyInfo k) {
        return Optional.ofNullable(keyVersionPurposes.get(k.getVersion()));
    }

    private static Optional<String> getTypeDescription(GPKeyInfo k) {
        if (k.getType() == GPKey.RSA_PUB_E || k.getType() == GPKey.RSA_PUB_N && k.getLength() > 0) {
            return Optional.of("RSA-" + k.getLength() * 8 + " public");
        } else if (k.getType() == GPKey.AES && k.getLength() > 0) {
            return Optional.of("AES-" + k.getLength() * 8);
        }
        return Optional.empty();
    }

    private static Optional<String> getKeyDescription(GPKeyInfo k) {
        Optional<String> t = getTypeDescription(k);
        Optional<String> p = getPurposeDescription(k);

        // Detect unaddressable factory keys
        Optional<String> f = k.getVersion() == 0x00 || k.getVersion() == 0xFF ? Optional.of("factory key") : Optional.empty();
        return Stream.of(t, p, f).filter(Optional::isPresent).map(Optional::get).reduce((a, b) -> a + ", " + b);
    }

    // Print the key template
    public static String toString(List<GPKeyInfo> list) {
        StringBuilder sb = new StringBuilder();
        for (GPKeyInfo k : list) {
            // print
            String description = getKeyDescription(k).map(e -> " (" + e + ")").orElse("");
            sb.append(String.format("Version: %3d (0x%02X) ID: %3d (0x%02X) type: %-12s length: %3d%s%n", k.getVersion(), k.getVersion(), k.getID(), k.getID(), k.getType(), k.getLength(), description));
        }
        return sb.toString();
    }

    public int getID() {
        return id;
    }

    public int getVersion() {
        return version;
    }

    public int getLength() {
        return length;
    }

    public GPKey getType() {
        return type;
    }

    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append("type=" + type);
        if (version >= 1 && version <= 0x7f)
            s.append(" version=" + GPUtils.intString(version));
        if (id >= 0 && id <= 0x7F)
            s.append(" id=" + GPUtils.intString(id));
        s.append(" len=" + length);
        return s.toString();
    }


    static class GPKeyInfoElement {
        final GPKey key;
        final int keyLength;
        final int templateLength;


        public static GPKeyInfoElement fromExtendedBytes(byte[] buf, int offset) {
            final int templateLength;
            if (buf[offset] != (byte) 0xFF) {
                logger.warn("Extended key element not starting with 0xFF!");
                templateLength = 3;
            } else {
                offset++; // Valid 0xFF as extended indicator
                templateLength = 4;
            }
            return new GPKeyInfoElement(GPKey.get(buf[offset++] & 0xFF).get(), (buf[offset++] << 8) + (buf[offset++] & 0xFF), templateLength);
        }

        GPKeyInfoElement(GPKey element, int elementLength, int templateLength) {
            this.key = element;
            this.templateLength = templateLength;
            this.keyLength = elementLength;
        }

        public GPKeyInfoElement(byte[] buf, int offset) {
            if (buf[offset] == (byte) 0xFF) {
                logger.trace("Parsing E {}", HexUtils.bin2hex(Arrays.copyOfRange(buf, offset, offset + 4)));
                // extended length
                key = GPKey.get(buf[++offset] & 0xFF).get();
                keyLength = (buf[++offset] << 8) + (buf[++offset] & 0xFF);
                templateLength = 4;
            } else {
                logger.trace("Parsing B {}", HexUtils.bin2hex(Arrays.copyOfRange(buf, offset, offset + 2)));
                key = GPKey.get(buf[offset++] & 0xFF).get();
                // Page 162 of GP 2.3.1 "the indicated length shall be set to '00' (meaning ‘greater than or equal to 256 bytes’)"
                int l = buf[offset++] & 0xFF;
                keyLength = l == 0x00 ? 256 : l;
                templateLength = 2;
            }
        }

        public static boolean isValid(GPKeyInfoElement e) {
            return e.key != GPKey.PRIVATE && e.key != GPKey.RFU_ASYMMETRICAL && e.key != GPKey.RFU_SYMMETRICAL;
        }

        @Override
        public String toString() {
            return "GPKeyInfoElement{" +
                    "key=" + key +
                    ", keyLength=" + keyLength +
                    ", templateLength=" + templateLength +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            GPKeyInfoElement that = (GPKeyInfoElement) o;
            return keyLength == that.keyLength &&
                    templateLength == that.templateLength &&
                    key == that.key;
        }

        @Override
        public int hashCode() {
            return Objects.hash(key, keyLength, templateLength);
        }
    }

    // GP 2.1.1 9.1.6
    // GP 2.2.1/2.3.1 11.1.8
    public enum GPKey {
        // Special
        PRIVATE(0x00, "Reserved for private use"),
        EXTENDED(0xFF, "Extended format"),
        RFU_SYMMETRICAL(0x86, "RFU (symmetric algorithm)"),
        RFU_ASYMMETRICAL(0xA9, "RFU (asymmetric algorithm)"),
        // Symmetrical
        DES3(0x80, "DES - mode (ECB/CBC) implicitly known"),
        DES3_RESERVED(0x81, "Reserved (Triple DES)"),
        DES3_CBC(0x82, "Triple DES in CBC mode"),
        DES_ECB(0x83, "DES in ECB mode"),
        DES_CBC(0x84, "DES in CBC mode"),
        PSK_TLS(0x85, "Pre-Shared Key for Transport Layer Security"),
        AES(0x88, "AES (16, 24, or 32 long keys)"),
        HMAC_SHA1(0x90, "HMAC-SHA1 - length of HMAC is implicitly known"),
        HMAC_SHA1_160(0x91, "MAC-SHA1-160 - length of HMAC is 160 bits"),
        // Asymmetrical
        RSA_PUB_E(0xA0, "RSA Public Key - public exponent e component (clear text)"),
        RSA_PUB_N(0xA1, "RSA Public Key - modulus N component (clear text)"),
        RSA_PRIV_N(0xA2, "RSA Private Key - modulus N component"),
        RSA_PRIV_D(0xA3, "RSA Private Key - private exponent d component"),
        RSA_PRIV_P(0xA4, "RSA Private Key - Chinese Remainder P component"),
        RSA_PRIV_Q(0xA5, "RSA Private Key - Chinese Remainder Q component"),
        RSA_PRIV_PQ(0xA6, "RSA Private Key - Chinese Remainder PQ component"),
        RSA_PRIV_DP1(0xA7, "RSA Private Key - Chinese Remainder DP1 component"),
        RSA_PRIV_DQ1(0xA8, "RSA Private Key - Chinese Remainder DQ1 component"),
        EC_PUB(0xB0, "ECC public key"),
        EC_PRIV(0xB1, "ECC private key"),
        EC_FIELD_P(0xB2, "ECC field parameter P (field specification)"),
        EC_FIELD_A(0xB3, "ECC field parameter A (first coefficient)"),
        EC_FIELD_B(0xB4, "ECC field parameter B (second coefficient)"),
        EC_FIELD_G(0xB5, "ECC field parameter G (generator)"),
        EC_FIELD_N(0xB6, "ECC field parameter N (order of generator)"),
        EC_FIELD_K(0xB7, "ECC field parameter k (cofactor of order of generator)"),
        EC_PARAM_REF(0xF0, "ECC key parameters reference");


        private final int type;
        private final String description;

        GPKey(int type, String desc) {
            this.type = type;
            this.description = desc;
        }

        public int getType() {
            return this.type;
        }

        public String getDescription() {
            return this.description;
        }

        public static Optional<GPKey> get(int type) {
            final GPKey result;
            if ((0x00 <= type) && (type <= 0x7f))
                result = PRIVATE;
            else if (type == 0x86 || type == 0x87 || ((0x89 <= type) && (type <= 0x8F)) || ((0x92 <= type) && (type <= 0x9F)))
                result = RFU_SYMMETRICAL;
            else if ((0xA9 <= type) && (type <= 0xAF))
                result = RFU_ASYMMETRICAL;
            else if ((0xB8 <= type) && (type <= 0xEF))
                result = RFU_ASYMMETRICAL;
            else if ((0xF1 <= type) && (type <= 0xFE))
                result = RFU_ASYMMETRICAL;
            else
                return Arrays.stream(values()).filter(e -> e.type == type).findFirst();
            return Optional.ofNullable(result);
        }

        public String typeName() {
            if (this == DES3 || this == DES3_RESERVED) {
                return "3DES";
            } else if (this == RSA_PUB_N || this == RSA_PUB_E) {
                return "RSA";
            } else if (this == EC_PUB) {
                return "EC";
            } else return name();
        }
    }
}
