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
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// Encapsulates key metadata
public final class GPKeyInfo {
    private static final Logger logger = LoggerFactory.getLogger(GPKeyInfo.class);

    private Type type;
    private int version = 0; // 1..7f
    private int id = -1; // 0..7f
    private int length = -1;

    // Called when parsing KeyInfo template
    GPKeyInfo(int version, int id, int length, int type) {
        this.version = version;
        this.id = id;
        this.length = length;
        // FIXME: these values should be encapsulated somewhere
        // FIXME: 0x81 is actually reserved according to GP
        // GP 2.2.1 11.1.8 Key Type Coding
        if (type == 0x80 || type == 0x81 || type == 0x82) {
            this.type = Type.DES3;
        } else if (type == 0x88) {
            this.type = Type.AES;
        } else if (type == 0xA1 || type == 0xA0) {
            this.type = Type.RSAPUB;
        } else if (type == 0x85) {
            this.type = Type.PSK;
        } else {
            throw new UnsupportedOperationException(String.format("Only AES, 3DES, PSK and RSA public keys are supported currently: 0x%02X", type));
        }
    }

    // GP 2.1.1 9.3.3.1
    // GP 2.2.1 11.3.3.1 and 11.1.8
    public static List<GPKeyInfo> parseTemplate(byte[] data) throws GPException {
        List<GPKeyInfo> r = new ArrayList<>();
        if (data == null || data.length == 0)
            return r;

        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(data);
        GPUtils.trace_tlv(data, logger);

        BerTlv keys = tlvs.find(new BerTag(0xE0));
        if (keys != null && keys.isConstructed()) {
            for (BerTlv key : keys.findAll(new BerTag(0xC0))) {
                byte[] tmpl = key.getBytesValue();
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
                int type = tmpl[offset++] & 0xFF;
                boolean extended = type == 0xFF;
                if (extended) {
                    // extended key type, use second byte
                    type = tmpl[offset++] & 0xFF;
                }
                // parse length
                int length = tmpl[offset++] & 0xFF;
                if (extended) {
                    length = length << 8 | tmpl[offset++] & 0xFF;
                }
                if (extended) {
                    // XXX usage and access is not shown currently
                    logger.warn("Extended format not parsed: " + HexUtils.bin2hex(Arrays.copyOfRange(tmpl, tmpl.length - 4, tmpl.length)));
                }
                // XXX: RSAPUB keys have two components A1 and A0, gets called with A1 and A0 (exponent) discarded
                r.add(new GPKeyInfo(version, id, length, type));
            }
        }
        return r;
    }

    // Print the key template
    public static void print(List<GPKeyInfo> list, PrintStream out) {
        boolean factory_keys = false;
        out.flush();
        for (GPKeyInfo k : list) {
            // Descriptive text about the key
            final String nice;
            if (k.getType() == Type.RSAPUB && k.getLength() > 0) {
                nice = "(RSA-" + k.getLength() * 8 + " public)";
            } else if (k.getType() == Type.AES && k.getLength() > 0) {
                nice = "(AES-" + k.getLength() * 8 + ")";
            } else {
                nice = "";
            }

            // Detect unaddressable factory keys
            if (k.getVersion() == 0x00 || k.getVersion() == 0xFF)
                factory_keys = true;

            // print
            out.println(String.format("Version: %3d (0x%02X) ID: %3d (0x%02X) type: %-4s length: %3d %s", k.getVersion(), k.getVersion(), k.getID(), k.getID(), k.getType(), k.getLength(), nice));
        }
        if (factory_keys) {
            out.println("Key version suggests factory keys");
        }
        out.flush();
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

    public Type getType() {
        return type;
    }

    public String toString() {
        StringBuffer s = new StringBuffer();
        s.append("type=" + type);
        if (version >= 1 && version <= 0x7f)
            s.append(" version=" + String.format("%d (0x%02X)", version, version));
        if (id >= 0 && id <= 0x7F)
            s.append(" id=" + String.format("%d (0x%02X)", id, id));
        s.append(" len=" + length);
        return s.toString();
    }

    public enum Type {
        DES3, AES, RSAPUB, PSK;

        @Override
        public String toString() {
            if (this.name().equals("RSAPUB"))
                return "RSA";
            return super.toString();
        }
    }


    // GP 2.1.1 9.1.6
    // GP 2.2.1 11.1.8
    public static String type2str(int type) {
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
}
