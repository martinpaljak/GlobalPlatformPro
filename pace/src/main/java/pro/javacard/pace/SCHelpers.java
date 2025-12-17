package pro.javacard.pace;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import pro.javacard.tlv.TLV;

import java.util.ArrayList;
import java.util.List;

class SCHelpers {
    static void dump(TLV tlv, int depth, List<String> result) {
        if (tlv.hasChildren()) {
            result.add(String.format("%s[%s]", " ".repeat(depth * 5), Hex.toHexString(tlv.tag().bytes())));

            for (TLV child : tlv.children()) {
                dump(child, depth + 1, result);
            }
        } else {
            result.add(String.format("%s[%s] %s", " ".repeat(depth * 5), Hex.toHexString(tlv.tag().bytes()), Hex.toHexString(tlv.value())));
        }
    }

    static void dump(List<TLV> list, int depth, List<String> result) {
        for (TLV t : list) {
            dump(t, depth, result);
        }
    }

    public static List<String> visualize_tlv(byte[] payload) {
        ArrayList<String> result = new ArrayList<>();
        try {
            var tlvs = TLV.parse(payload);
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
