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

import apdu4j.APDUBIBO;
import apdu4j.CommandAPDU;
import apdu4j.ResponseAPDU;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvBuilder;
import pro.javacard.AID;

import java.io.IOException;

/**
 * SE Access Control utility.
 */
public final class SEAccessControlUtility {

    /*
     * Send Access Control rule GET DATA.
     */
    private static ResponseAPDU sendAcrGetData(final APDUBIBO channel, final byte P1) throws IOException, GPException {
        CommandAPDU list = new CommandAPDU(GPSession.CLA_GP, GPSession.INS_GET_DATA, 0xFF, P1, 256);

        ResponseAPDU response = channel.transmit(list);

        try {
            GPException.check(response, "ACR GET DATA failed");
        } catch (GPException e) {
            if (SEAccessControl.ACR_GET_DATA_ERROR.containsKey(e.sw)) {
                System.out.println("[SW] " + SEAccessControl.ACR_GET_DATA_ERROR.get(e.sw));
            }
            throw e;
        }
        return response;
    }

    /*
     * List access rules.
     */
    public static void acrList(final GPSession gp) throws IOException, GPException {
        try {
            gp.select(SEAccessControl.ACR_AID);

            ResponseAPDU response = sendAcrGetData(gp.getCardChannel(), SEAccessControl.ACR_GET_DATA_ALL);
            SEAccessControl.BerTlvData temp = SEAccessControl.AcrListResponse.getAcrListData(null, response.getData());

            while (temp.getCurrentIndex() < temp.getLength()) {
                response = sendAcrGetData(gp.getCardChannel(), SEAccessControl.ACR_GET_DATA_NEXT);
                temp = SEAccessControl.AcrListResponse.getAcrListData(temp, response.getData());
            }

            SEAccessControl.AcrListResponse resp = SEAccessControl.AcrListResponse.fromBytes(temp.getData());
            SEAccessControl.printList(resp.acrList);
        } catch (GPException e) {
            throw new GPException("Could not read " + SEAccessControl.ACR_AID);
        }
    }

    /*
     * Add an access rule.
     */
    public static void acrAdd(final GPSession gp, final AID araAid, final AID aid, final byte[] hash, final byte[] rules) throws IOException, GPException {
        SEAccessControl.RefArDo refArDo = new SEAccessControl.RefArDo(aid, hash, rules);
        SEAccessControl.StoreArDo storeArDo = new SEAccessControl.StoreArDo(refArDo);
        acrStore(gp, araAid, storeArDo.toTlv());
    }

    /*
     * Send store data for access rule.
     */
    public static void acrStore(final GPSession gp, final AID araAid, final BerTlv data) throws IOException, GPException {
        try {
            //0x90 is for getting BER-TLV data (Secure Element Access Control v1.0 p36)
            gp.personalizeSingle(araAid, new BerTlvBuilder().addBerTlv(data).buildArray(), (byte) 0x90);
        } catch (GPException e) {
            if (SEAccessControl.ACR_STORE_DATA_ERROR.containsKey(e.sw)) {
                System.out.println("[SW] " + SEAccessControl.ACR_STORE_DATA_ERROR.get(e.sw));
            } else {
                System.out.println(e.getMessage());
            }
        }
    }

    /*
     * Delete an access rule by AID/HASH.
     */
    public static void acrDelete(final GPSession gp, final AID araAid, final AID aid, final byte[] hash) throws IOException, GPException {
        BerTlv request;

        if (hash != null) {
            SEAccessControl.RefArDo refArDo = new SEAccessControl.RefArDo(aid, hash, null);
            request = new SEAccessControl.DeleteArDo(refArDo).toTlv();
        } else if (aid != null) {
            SEAccessControl.AidRefDo aidRefDo = new SEAccessControl.AidRefDo(aid.getBytes());
            request = new SEAccessControl.DeleteAidDo(aidRefDo).toTlv();
        } else {
            request = new SEAccessControl.DeleteAll().toTlv();
        }
        acrStore(gp, araAid, request);
    }
}
