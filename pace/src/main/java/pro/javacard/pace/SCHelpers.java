package pro.javacard.pace;

import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;

class SCHelpers {
    static String spacer(int n) {
        return new String(new char[n]).replace('\0', ' ');
    }

    static void dump(BerTlv tlv, int depth, List<String> result) {
        if (tlv.isConstructed()) {
            result.add(String.format("%s[%s]", spacer(depth * 5), Hex.toHexString(tlv.getTag().bytes)));

            for (BerTlv child : tlv.getValues()) {
                dump(child, depth + 1, result);
            }
        } else {
            result.add(String.format("%s[%s] %s", spacer(depth * 5), Hex.toHexString(tlv.getTag().bytes), Hex.toHexString(tlv.getBytesValue())));
        }
    }

    static void dump(BerTlvs tlv, int depth, List<String> result) {
        for (BerTlv t : tlv.getList()) {
            dump(t, depth, result);
        }
    }

    public static List<String> visualize_tlv(byte[] payload) {
        ArrayList<String> result = new ArrayList<>();
        try {
            BerTlvs tlvs = new BerTlvParser().parse(payload);
            dump(tlvs, 0, result);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException("Not valid TLVs: " + e.getMessage(), e);
        }
        return result;
    }

    static void trace_tlv(byte[] data, Logger l) {
        try {
            for (String s : visualize_tlv(data))
                l.trace(s);
        } catch (IllegalArgumentException e) {
            l.error("Invalid TLV data: {}", Hex.toHexString(data), e);
        }
    }
}
