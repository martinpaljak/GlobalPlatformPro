/*
 * The MIT License (MIT)
 * <p/>
 * Copyright (c) 2017 Bertrand Martel
 * <p/>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p/>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p/>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package pro.javacard.gp;

import apdu4j.HexUtils;
import com.payneteasy.tlv.*;
import org.bouncycastle.util.Arrays;
import pro.javacard.AID;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Access control Rules implementation (reference document : Secure Element Access Control Version 1.0).
 *
 * @author Bertrand Martel
 */
public class SEAccessControl {

    public final static AID ACR_AID = new AID("A00000015141434C00");

    public final static byte ACR_GET_DATA_ALL = 0x40;
    public final static byte ACR_GET_DATA_NEXT = 0x60;
    /**
     * Store data status work (p44 Secure Element Access control spec v1.0)
     */
    public final static Map<Integer, String> ACR_STORE_DATA_ERROR;
    /**
     * Get Data status word (p27 Secure Element Access control spec v1.0)
     */
    public final static Map<Integer, String> ACR_GET_DATA_ERROR;
    private final static byte[] ACR_GET_DATA_RESP = new byte[]{(byte) 0xFF, (byte) 0x40};

    //Access Rule reference data object (p45 Secure Element Access control spec v1.0)
    private final static byte REF_AR_DO = (byte) 0xE2;
    private final static byte REF_DO = (byte) 0xE1;
    private final static byte AID_REF_DO = (byte) 0x4F;
    private final static byte HASH_REF_DO = (byte) 0xC1;
    private final static byte AR_DO = (byte) 0xE3;
    private final static byte APDU_AR_DO = (byte) 0xD0;
    private final static byte NFC_AR_DO = (byte) 0xD1;
    // Google extensions
    private final static byte GOOGLE_PKG_DO = (byte) 0xCA;

    //command message data object (p38 Secure Element Access control spec v1.0)
    private final static byte STORE_AR_DO = (byte) 0xF0;
    private final static byte DELETE_AR_DO = (byte) 0xF1;

    static {
        Map<Integer, String> tmp = new HashMap<>();
        tmp.put(0x6381, "Rule successfully stored but an access rule already exists for this target");
        tmp.put(0x6581, "Memory problem");
        tmp.put(ISO7816.SW_WRONG_LENGTH, "Wrong length in Lc");
        tmp.put(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, "Security status not satisfied");
        tmp.put(ISO7816.SW_CONDITIONS_OF_USE_NOT_SATISFIED, "Conditions not satisfied");
        tmp.put(ISO7816.SW_WRONG_DATA, "Incorrect values in the command data");
        tmp.put(ISO7816.SW_OUT_OF_MEMORY, "Not enough memory space");
        tmp.put(ISO7816.SW_INCORRECT_P1P2, "Incorrect P1 P2");
        tmp.put(ISO7816.SW_KEY_NOT_FOUND, "Referenced data not found");
        tmp.put(0x6A89, "Conflicting access rule already exists in the Secure Element");
        tmp.put(ISO7816.SW_INS_NOT_SUPPORTED, "Invalid instruction");
        tmp.put(ISO7816.SW_CLA_NOT_SUPPORTED, "Invalid class");
        ACR_STORE_DATA_ERROR = Collections.unmodifiableMap(tmp);
    }

    static {
        Map<Integer, String> tmp = new HashMap<>();
        tmp.put(0x6581, "Memory problem");
        tmp.put(ISO7816.SW_WRONG_LENGTH, "Wrong length in Lc");
        tmp.put(ISO7816.SW_CONDITIONS_OF_USE_NOT_SATISFIED, "Conditions not satisfied");
        tmp.put(ISO7816.SW_WRONG_DATA, "Incorrect values in the command data");
        tmp.put(ISO7816.SW_INCORRECT_P1P2, "Incorrect P1 P2");
        tmp.put(ISO7816.SW_KEY_NOT_FOUND, "Referenced data not found");
        tmp.put(ISO7816.SW_INS_NOT_SUPPORTED, "Invalid instruction");
        tmp.put(ISO7816.SW_CLA_NOT_SUPPORTED, "Invalid class");
        ACR_GET_DATA_ERROR = Collections.unmodifiableMap(tmp);
    }

    private static BerTlv buildArDoData(final ApduArDo apduArDo, final NfcArDo nfcArDo) {
        if (apduArDo != null && nfcArDo == null) {
            return apduArDo.toTlv();
        }
        if (apduArDo == null && nfcArDo != null) {
            return nfcArDo.toTlv();
        }
        if (apduArDo != null && nfcArDo != null) {
            return new BerTlvBuilder().addBerTlv(apduArDo.toTlv()).addBerTlv(nfcArDo.toTlv()).buildTlv();
        }
        return null;
    }

    private static byte[] buildApduArDoData(final EventAccessRules rule, final byte[] filter) {
        if (rule == EventAccessRules.CUSTOM) {
            return filter;
        } else if (rule == EventAccessRules.NONE) {
            return new byte[]{};
        } else {
            return new byte[]{rule.getValue()};
        }
    }

    /*
     * Parse REF_AR_DO object (p46 Secure Element Access Control v1.0).
     * <p>
     * <p>
     * 0xE2 | length | REF-DO | AR-DO
     * </p>
     */
    public static RefArDo parseRefArDo(final BerTlv refArDo) throws GPDataException {
        RefDo refDo = parseRefDo(refArDo.find(new BerTag(REF_DO)));
        ArDo arDo = parseArDo(refArDo.find(new BerTag(AR_DO)));
        return new RefArDo(refDo, arDo);
    }

    /*
     * Parse REF_DO object (p46 Secure Element Access control v1.0).
     * <p>
     * <p>
     * 0xE1 | length | AID-REF-DO | Hash-REF-DO
     * </p>
     */
    public static RefDo parseRefDo(final BerTlv refDo) throws GPDataException {
        AidRefDo aidRefDo = parseAidRefDo(refDo.find(new BerTag(AID_REF_DO)));
        HashRefDo hashRefDo = parseHashRefDo(refDo.find(new BerTag(HASH_REF_DO)));
        return new RefDo(aidRefDo, hashRefDo);
    }

    /*
     * Parse AID_REF_DO object (p45 Secure Element Access Control v1.0).
     * <p>
     * 4F | length | AID
     */
    public static AidRefDo parseAidRefDo(final BerTlv aidRefDo) throws GPDataException {
        return new AidRefDo(aidRefDo != null ? aidRefDo.getBytesValue() : new byte[]{});
    }

    /*
     * Parse HASH_REF_DO (p46 Secure Element Access Control v1.0).
     * <p>
     * C1 | length | hash
     */
    public static HashRefDo parseHashRefDo(final BerTlv hashRefDo) throws GPDataException {
        return new HashRefDo(hashRefDo != null ? hashRefDo.getBytesValue() : new byte[]{});
    }

    /*
     * Parse AR_DO (p47 Secure Element Access Control v1.0)
     * <p>
     * E3 | length | APDU-AR-DO
     * <p>
     * OR
     * <p>
     * E3 | length | NFC-AR-DO
     * <p>
     * OR
     * <p>
     * E3 | length | APDU-AR-DO | NFC-AR-DO
     */
    public static ArDo parseArDo(final BerTlv arDo) throws GPDataException {
        if (arDo != null) {
            ApduArDo apduArDo = parseApduArDo(arDo.find(new BerTag(APDU_AR_DO)));
            NfcArDo nfcArDo = parseNfcArDo(arDo.find(new BerTag(NFC_AR_DO)));
            return new ArDo(apduArDo, nfcArDo);
        }
        return null;
    }

    /*
     * Parse APDU_AR_DO (p48 Secure Element Access Control v1.0).
     * <p>
     * D0 | length | 0x00 or 0x01 or APDU filter 1 | APDU filter n
     */
    public static ApduArDo parseApduArDo(final BerTlv apduArDo) throws GPDataException {
        if (apduArDo != null) {
            byte[] data = apduArDo.getBytesValue();
            if (data.length == 1) {
                switch (data[0] & 0xFF) {
                    case 0x01:
                        return new ApduArDo(EventAccessRules.ALWAYS, new byte[]{});
                    case 0x00:
                        return new ApduArDo(EventAccessRules.NEVER, new byte[]{});
                }
            } else {
                return new ApduArDo(EventAccessRules.CUSTOM, data);
            }
        }
        return null;
    }

    /*
     * Parse NFC_AR_DO (p49 Secure Element Access Control v1.0).
     * <p>
     * D1 | 01 | 0x00 or 0x01
     */
    public static NfcArDo parseNfcArDo(final BerTlv nfcArDo) throws GPDataException {
        if (nfcArDo != null) {
            switch (nfcArDo.getBytesValue()[0]) {
                case 0x01:
                    return new NfcArDo(EventAccessRules.ALWAYS);
                case 0x00:
                    return new NfcArDo(EventAccessRules.NEVER);
            }
        }
        return null;
    }

    /*
     * Print ACR list response.
     */
    public static void printList(final List<RefArDo> acrList) {
        if (acrList.size() == 0) {
            System.out.println("No rules found");
            return;
        }

        for (int i = 0; i < acrList.size(); i++) {
            RefArDo r = acrList.get(i);
            System.out.println("RULE #" + i + " :");
            if (r.refDo.aidRefDo.aid.length > 0)
                System.out.println("       AID  : " + r.refDo.aidRefDo);
            if (r.refDo.hashRefDo.hash.length > 0)
                System.out.println("       HASH : " + r.refDo.hashRefDo);
            if (r.arDo != null) {
                if (r.arDo.apduArDo != null) {
                    System.out.println("       APDU rule   : " + r.arDo.apduArDo.rule + "(" + String.format("0x%02X", r.arDo.apduArDo.rule.getValue()) + ")");
                    if (r.arDo.apduArDo.filter.length > 0)
                        System.out.println("       APDU filter : " + HexUtils.bin2hex(r.arDo.apduArDo.filter));
                }
                if (r.arDo.nfcArDo != null) {
                    System.out.println("       NFC  rule   : " + r.arDo.nfcArDo.rule + "(" + String.format("0x%02X", r.arDo.nfcArDo.rule.getValue()) + ")");
                }
            }
        }
    }

    /**
     * event access rule used by NFC-AR-DO and APDU-AR-DO (p48 + p49)
     */
    enum EventAccessRules {
        NEVER((byte) 0x00),
        ALWAYS((byte) 0x01),
        CUSTOM((byte) 0x02),
        NONE((byte) 0x03);

        private byte value;

        EventAccessRules(final byte value) {
            this.value = value;
        }

        public byte getValue() {
            return value;
        }
    }

    interface ITLV {
        BerTlv toTlv();
    }

    /**
     * Command-Delete-AR-DO (p39) for deleting AID-REF-DO
     */
    public static class DeleteAidDo implements ITLV {

        final AidRefDo aidRefDo;

        public DeleteAidDo(final AidRefDo aidRefDo) {
            this.aidRefDo = aidRefDo;
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder(new BerTag(DELETE_AR_DO))
                    .addBerTlv(aidRefDo.toTlv())
                    .buildTlv();
        }
    }

    /**
     * Command-Delete-AR-DO (p39) for deleting AR-DO
     */
    public static class DeleteArDo implements ITLV {

        final RefArDo refArDo;

        public DeleteArDo(final RefArDo refArDo) {
            this.refArDo = refArDo;
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder(new BerTag(DELETE_AR_DO))
                    .addBerTlv(refArDo.toTlv())
                    .buildTlv();
        }
    }


    /**
     * Command-Delete-AR-DO (p39) for deleting AR-DO
     */
    public static class DeleteAll implements ITLV {

        public DeleteAll() {
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder(new BerTag(DELETE_AR_DO))
                    .buildTlv();
        }
    }

    /**
     * Command-Store-AR-DO (p38)
     */
    public static class StoreArDo implements ITLV {

        final RefArDo refArDo;

        public StoreArDo(final RefArDo refArDo) {
            this.refArDo = refArDo;
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder(new BerTag(STORE_AR_DO))
                    .addBerTlv(refArDo.toTlv())
                    .buildTlv();
        }
    }

    /**
     * REF-AR-DO (p46) composed of REF-DO | AR-DO
     */
    public static class RefArDo implements ITLV {

        final RefDo refDo;
        final ArDo arDo;

        public RefArDo(final RefDo refDo, final ArDo arDo) {
            this.refDo = refDo;
            this.arDo = arDo;
        }

        public RefArDo(final AID aid, final byte[] hash, final byte[] rules) {
            this.refDo = new RefDo(new AidRefDo(aid == null ? new byte[0] : aid.getBytes()), new HashRefDo(hash == null ? new byte[0] : hash));
            this.arDo = new ArDo(new ApduArDo(rules), null);
        }

        @Override
        public BerTlv toTlv() {
            BerTlvBuilder aggregate = new BerTlvBuilder()
                    .addBerTlv(refDo.toTlv())
                    .addBerTlv(arDo.toTlv());
            return new BerTlvBuilder(new BerTag(REF_AR_DO)).add(aggregate).buildTlv();
        }

        public String toString() {
            return refDo + " | " + arDo;
        }
    }

    /**
     * REF-DO (p46) composed of AID-REF-DO | Hash-REF-DO
     */
    public static class RefDo implements ITLV {
        final AidRefDo aidRefDo;
        final HashRefDo hashRefDo;

        public RefDo(final AidRefDo aidRefDo, final HashRefDo hashRefDo) {
            this.aidRefDo = aidRefDo;
            this.hashRefDo = hashRefDo;
        }

        public String toString() {
            return aidRefDo + " | " + hashRefDo;
        }

        @Override
        public BerTlv toTlv() {
            BerTlvBuilder aggregate = new BerTlvBuilder().addBerTlv(aidRefDo.toTlv()).addBerTlv(hashRefDo.toTlv());
            return new BerTlvBuilder(new BerTag(REF_DO))
                    .add(aggregate)
                    .buildTlv();
        }
    }

    /**
     * AID-REF-DO data object (p45)
     */
    public static class AidRefDo implements ITLV {
        final byte[] aid;

        public AidRefDo(final byte[] data) {
            if (data == null)
                aid = new byte[0];
            else
                aid = Arrays.copyOf(data, data.length);
        }

        public String toString() {
            return HexUtils.bin2hex(aid);
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder()
                    .addBytes(new BerTag(AID_REF_DO), aid)
                    .buildTlv();
        }
    }

    /**
     * Hash-REF-DO (p46)
     */
    public static class HashRefDo implements ITLV {
        final byte[] hash;

        public HashRefDo(final byte[] data) {
            if (data == null)
                hash = new byte[0];
            else
                hash = Arrays.copyOf(data, data.length);
        }

        public String toString() {
            return HexUtils.bin2hex(hash);
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder()
                    .addBytes(new BerTag(HASH_REF_DO), hash)
                    .buildTlv();
        }
    }

    /**
     * PKG-REF-DO (CA) (Android extension)
     */
    public static class PkgRefDo implements ITLV {
        final String pkg;

        public PkgRefDo(final byte[] data) {
            pkg = new String(data, StandardCharsets.US_ASCII);
        }

        public String toString() {
            return pkg;
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder()
                    .addBytes(new BerTag(GOOGLE_PKG_DO), pkg.getBytes(StandardCharsets.US_ASCII))
                    .buildTlv();
        }
    }

    /**
     * AR-DO access rule data object (p47) composed of APDU-AR-DO or NFC-AR-DO or APDU-AR-DO | NFC-AR-DO
     */
    public static class ArDo implements ITLV {

        final ApduArDo apduArDo;
        final NfcArDo nfcArDo;

        public ArDo(final ApduArDo apduArDo, final NfcArDo nfcArDo) {
            this.apduArDo = apduArDo;
            this.nfcArDo = nfcArDo;
        }

        public String toString() {
            return "apdu : " + apduArDo + " | nfc : " + nfcArDo;
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder(new BerTag(AR_DO))
                    .addBerTlv(buildArDoData(apduArDo, nfcArDo))
                    .buildTlv();
        }
    }

    /**
     * APDU-AR-DO access rule data object (p48).
     */
    public static class ApduArDo implements ITLV {

        final EventAccessRules rule;
        final byte[] filter;

        public ApduArDo(final EventAccessRules rule, final byte[] filter) {
            this.rule = rule;
            this.filter = Arrays.copyOf(filter, filter.length);
        }

        public ApduArDo(final byte[] data) {
            if (data != null && data.length == 1) {
                switch (data[0]) {
                    case 0x00:
                        this.rule = EventAccessRules.NEVER;
                        break;
                    case 0x01:
                        this.rule = EventAccessRules.ALWAYS;
                        break;
                    default:
                        this.rule = EventAccessRules.CUSTOM;
                        break;
                }
                this.filter = new byte[data.length];
            } else if (data != null) {
                this.rule = EventAccessRules.CUSTOM;
                this.filter = new byte[data.length];
            } else {
                this.rule = EventAccessRules.NONE;
                this.filter = new byte[]{};
            }
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder()
                    .addBytes(new BerTag(APDU_AR_DO), buildApduArDoData(rule, filter))
                    .buildTlv();
        }

        public String toString() {
            return "rule : " + rule + " | filter : " + HexUtils.bin2hex(filter);
        }
    }

    /**
     * NFC-AR-DO access rule data object.
     */
    public static class NfcArDo implements ITLV {

        final EventAccessRules rule;

        public NfcArDo(final EventAccessRules rule) {
            this.rule = rule;
        }

        @Override
        public BerTlv toTlv() {
            return new BerTlvBuilder()
                    .addBytes(new BerTag(NFC_AR_DO), new byte[]{rule.getValue()})
                    .buildTlv();
        }

        public String toString() {
            return "rule : " + rule;
        }
    }

    public static class BerTlvData {
        /**
         * data aggregated from the first get data request.
         */
        private final byte[] data;

        /**
         * full data length .
         */
        private final int length;

        /**
         * current processing index.
         */
        private int currentIndex;

        public BerTlvData(final byte[] data, final int length, final int index) {
            this.data = Arrays.copyOf(data, data.length);
            this.length = length;
            this.currentIndex = index;
        }

        public byte[] getData() {
            return Arrays.copyOf(data, data.length);
        }

        public void addData(final byte[] source) {
            System.arraycopy(source, 0, data, currentIndex, source.length);
            currentIndex += source.length;
        }

        public int getLength() {
            return length;
        }

        public int getCurrentIndex() {
            return currentIndex;
        }
    }

    /*
     * Parse access rule list response.
     */
    public static class AcrListResponse {

        public final List<RefArDo> acrList;

        public AcrListResponse(final List<RefArDo> acrList) {
            this.acrList = acrList;
        }

        public static BerTlvData getAcrListData(final BerTlvData previousData, final byte[] data) throws GPDataException {

            if (previousData == null &&
                    data.length > 2 &&
                    (data[0] == ACR_GET_DATA_RESP[0]) &&
                    (data[1] == ACR_GET_DATA_RESP[1])) {

                int first = data[2] & 0xFF; // fist byte determining length
                int length = 0; // actual length integer
                int offset = 3; //offset

                // FIXME: standard length
                if (first < 0x80) {
                    length = first & 0xFF;
                } else {
                    switch (first) {
                        case 0x81:
                            length = data[3] & 0xFF;
                            offset++;
                            break;
                        case 0x82:
                            length = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF);
                            offset += 2;
                            break;
                        case 0x83:
                            length = ((data[3] & 0xFF) << 16) | ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
                            offset += 3;
                            break;
                        default:
                            throw new GPDataException("ACR get data : bad BER TLV response format (GET_DATA)");
                    }
                }
                byte[] berData = new byte[length];
                System.arraycopy(data, offset, berData, 0, data.length - offset);
                return new BerTlvData(berData, length, data.length - offset);
            } else if (previousData != null) {
                previousData.addData(data);
                return previousData;
            } else {
                throw new GPDataException("ACR get data : bad response format (GET_DATA)");
            }
        }


        public static AcrListResponse fromBytes(final byte[] data) throws GPDataException {
            BerTlvParser parser = new BerTlvParser();

            List<RefArDo> acrList = new ArrayList<>();

            BerTlvs tlvs = parser.parse(data);

            for (BerTlv t : tlvs.findAll(new BerTag(REF_AR_DO))) {
                acrList.add(parseRefArDo(t));
            }
            return new AcrListResponse(acrList);
        }
    }

    public static class AcrListFetcher {
        final GPSession gp;

        public AcrListFetcher(GPSession gp) {
            this.gp = gp;
        }

        // Assumes a SD AID is selected
        public byte[] get(AID araAid) throws IOException, GPException {
            byte[] result = new byte[0];
            byte[] r;

            if (araAid != null) {
                r = gp.personalizeSingle(araAid, new byte[]{(byte) 0xf3, 0x00}, 0x10);
            } else {
                r = gp.storeDataSingle(new byte[]{(byte) 0xf5, 0x00}, 0x10);
            }

            int length = getLen(r, 2);
            result = GPUtils.concatenate(result, r);

            int i = 1;
            // XXX: This is not the most precise, but seems to work for now.
            while (result.length < length) {
                r = gp._storeDataSingle(new byte[]{(byte) 0xf5, 0x00}, 0x10, i++);
                result = GPUtils.concatenate(result, r);
            }
            return result;
        }

        public byte[] get() throws IOException, GPException {
            return get(null);
        }
    }

    // FIXME: standard length
    static int getLen(byte[] buffer, int offset) throws GPDataException {
        int first = buffer[offset] & 0xFF;
        final int length;

        if (first < 0x80) {
            length = first & 0xFF;
        } else if (first == 0x81) {
            length = buffer[offset + 1] & 0xFF;
        } else if (first == 0x82) {
            length = ((buffer[offset + 1] & 0xFF) << 8) | (buffer[offset + 2] & 0xFF);
        } else if (first == 0x83) {
            length = ((buffer[offset + 1] & 0xFF) << 16) | ((buffer[offset + 2] & 0xFF) << 8) | (buffer[offset + 3] & 0xFF);
        } else {
            throw new GPDataException("Invalid length", buffer);
        }
        return length;
    }

}
