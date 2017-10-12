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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import apdu4j.ISO7816;
import org.bouncycastle.util.Arrays;

import apdu4j.HexUtils;

/**
 * Access control Rules implementation (reference document : Secure Element Access Control Version 1.0).
 *
 * @author Bertrand Martel
 */
public class SEAccessControl {

	public final static AID ACR_AID = new AID("A00000015141434C00");

	public final static byte ACR_GET_DATA_ALL = 0x40;
	public final static byte ACR_GET_DATA_NEXT = 0x60;

	private final static byte[] ACR_GET_DATA_RESP = new byte[]{ (byte)0xFF, (byte)0x40 };

	//Access Rule reference data object (p45 Secure Element Access control spec v1.0)
	private final static byte REF_AR_DO = (byte) 0xE2;
	private final static byte REF_DO = (byte) 0xE1;
	private final static byte AID_REF_DO = (byte) 0x4F;
	private final static byte HASH_REF_DO = (byte) 0xC1;

	private final static byte AR_DO = (byte) 0xE3;
	private final static byte APDU_AR_DO = (byte) 0xD0;
	private final static byte NFC_AR_DO = (byte) 0xD1;

	//from Secure Element Access control spec p46, hash length can be 20 (sha1) or 0
	private final static byte HASH_MAX_LENGTH = (byte) 0x14;
	private final static byte HASH_MIN_LENGTH = (byte) 0x00;

	//command message data object (p38 Secure Element Access control spec v1.0)
	private final static byte STORE_AR_DO = (byte) 0xF0;
	private final static byte DELETE_AR_DO = (byte) 0xF1;

	/**
	 * Store data status work (p44 Secure Element Access control spec v1.0)
	 */
	public final static Map<Integer, String> ACR_STORE_DATA_ERROR = new HashMap<>();
	static {
		ACR_STORE_DATA_ERROR.put(0x6381, "Rule successfully stored but an access rule already exists for this target");
		ACR_STORE_DATA_ERROR.put(0x6581, "Memory problem");
		ACR_STORE_DATA_ERROR.put(ISO7816.SW_WRONG_LENGTH, "Wrong length in Lc");
		ACR_STORE_DATA_ERROR.put(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, "Security status not satisfied");
		ACR_STORE_DATA_ERROR.put(ISO7816.SW_CONDITIONS_OF_USE_NOT_SATISFIED, "Conditions not satisfied");
		ACR_STORE_DATA_ERROR.put(ISO7816.SW_WRONG_DATA, "Incorrect values in the command data");
		ACR_STORE_DATA_ERROR.put(ISO7816.SW_OUT_OF_MEMORY, "Not enough memory space");
		ACR_STORE_DATA_ERROR.put(ISO7816.SW_INCORRECT_P1P2, "Incorrect P1 P2");
		ACR_STORE_DATA_ERROR.put(ISO7816.SW_KEY_NOT_FOUND, "Referenced data not found");
		ACR_STORE_DATA_ERROR.put(0x6A89, "Conflicting access rule already exists in the Secure Element");
		ACR_STORE_DATA_ERROR.put(ISO7816.SW_INS_NOT_SUPPORTED, "Invalid instruction");
		ACR_STORE_DATA_ERROR.put(ISO7816.SW_CLA_NOT_SUPPORTED, "Invalid class");
	}

	/**
	 * Get Data status word (p27 Secure Element Access control spec v1.0)
	 */
	public final static Map<Integer, String> ACR_GET_DATA_ERROR = new HashMap<>();
	static {
		ACR_GET_DATA_ERROR.put(0x6581, "Memory problem");
		ACR_GET_DATA_ERROR.put(ISO7816.SW_WRONG_LENGTH, "Wrong length in Lc");
		ACR_GET_DATA_ERROR.put(ISO7816.SW_CONDITIONS_OF_USE_NOT_SATISFIED, "Conditions not satisfied");
		ACR_GET_DATA_ERROR.put(ISO7816.SW_WRONG_DATA, "Incorrect values in the command data");
		ACR_GET_DATA_ERROR.put(ISO7816.SW_INCORRECT_P1P2, "Incorrect P1 P2");
		ACR_GET_DATA_ERROR.put(ISO7816.SW_KEY_NOT_FOUND, "Referenced data not found");
		ACR_GET_DATA_ERROR.put(ISO7816.SW_INS_NOT_SUPPORTED, "Invalid instruction");
		ACR_GET_DATA_ERROR.put(ISO7816.SW_CLA_NOT_SUPPORTED, "Invalid class");
	}

	/**
	 * Interface for Tag Length value object
	 */
	interface ITLV {
		byte getTag();
		byte[] getData();
	}

	/**
	 * Common class for All TLV object reference in Secure Element Access Control spec
	 */
	public static abstract class TLV implements ITLV {

		/**
		 * All field are enabled by default.
		 */
		protected boolean enabled = true;

		/**
		 * Used to build the TLV object
		 */
		public byte[] getBytes(){
			byte[] tlvData = getData();
			byte[] data = new byte[tlvData.length + 2];
			data[0] = getTag();
			data[1] = (byte) tlvData.length;
			System.arraycopy(tlvData, 0, data, 2, tlvData.length);
			return data;
		}

		public void setEnable(boolean status){
			enabled = status;
		}
	}

	/**
	 * Command-Delete-AR-DO (p39) for deleting AID-REF-DO
	 */
	public static class DeleteAidDo extends TLV {
		AidRefDo aidRefDo;

		public DeleteAidDo(AidRefDo aidRefDo){
			this.aidRefDo = aidRefDo;
		}

		public byte getTag(){
			return DELETE_AR_DO;
		}

		public byte[] getData(){
			return aidRefDo.getBytes();
		}
	}

	/**
	 * Command-Delete-AR-DO (p39) for deleting AR-DO
	 */
	public static class DeleteArDo extends TLV {
		RefArDo refArDo;

		public DeleteArDo(RefArDo refArDo){
			this.refArDo = refArDo;
			if (this.refArDo.arDo.apduArDo != null)
				this.refArDo.arDo.apduArDo.setEnable(false);
			if (this.refArDo.arDo.nfcArDo != null)
				this.refArDo.arDo.nfcArDo.setEnable(false);
		}

		public byte getTag(){
			return DELETE_AR_DO;
		}

		public byte[] getData(){
			return refArDo.getBytes();
		}
	}

	/**
	 * Command-Store-AR-DO (p38)
	 */
	public static class StoreArDo extends TLV {
		RefArDo refArDo;

		public StoreArDo(RefArDo refArDo){
			this.refArDo = refArDo;
		}

		public byte getTag(){
			return STORE_AR_DO;
		}

		public byte[] getData(){
			return refArDo.getBytes();
		}
	}

	/**
	 * REF-AR-DO (p46) composed of REF-DO | AR-DO
	 */
	public static class RefArDo extends TLV {

		RefDo refDo;
		ArDo arDo;

		public RefArDo(RefDo refDo, ArDo arDo){
			this.refDo = refDo;
			this.arDo = arDo;
		}

		public RefArDo(AID aid, byte[] hash){
			this.refDo = new RefDo(new AidRefDo(aid.getBytes()), new HashRefDo(hash));
			this.arDo = new ArDo(new ApduArDo(EventAccessRules.ALWAYS, new byte[]{}), null);
		}

		public RefArDo(AID aid, byte[] hash, byte[] rules){
			this.refDo = new RefDo(new AidRefDo(aid.getBytes()), new HashRefDo(hash));
			this.arDo = new ArDo(new ApduArDo(rules), null);
		}

		public String toString(){
			return refDo + " | " + arDo;
		}

		public byte getTag(){
			return REF_AR_DO;
		}

		public byte[] getData(){
			byte[] refDoBytes = refDo.getBytes();
			byte[] arDoBytes = arDo.getBytes();

			byte[] data = new byte[refDoBytes.length + arDoBytes.length];
			System.arraycopy(refDoBytes, 0, data, 0, refDoBytes.length);
			System.arraycopy(arDoBytes, 0, data, refDoBytes.length, arDoBytes.length);
			return data;
		}
	}

	/**
	 * REF-DO (p46) composed of AID-REF-DO | Hash-REF-DO
	 */
	public static class RefDo extends TLV {
		AidRefDo aidRefDo;
		HashRefDo hashRefDo;

		public RefDo(AidRefDo aidRefDo, HashRefDo hashRefDo){
			this.aidRefDo = aidRefDo;
			this.hashRefDo = hashRefDo;
		}

		public String toString(){
			return aidRefDo + " | " + hashRefDo;
		}

		public byte getTag(){
			return REF_DO;
		}

		public byte[] getData(){
			byte[] aidRefBytes = aidRefDo.getBytes();
			byte[] hashRefBytes = hashRefDo.getBytes();

			byte[] data = new byte[aidRefBytes.length + hashRefBytes.length];
			System.arraycopy(aidRefBytes, 0, data, 0, aidRefBytes.length);
			System.arraycopy(hashRefBytes, 0, data, aidRefBytes.length, hashRefBytes.length);
			return data;
		}
	}

	/**
	 * AID-REF-DO data object (p45)
	 */
	public static class AidRefDo extends TLV {
		byte[] aid;

		public AidRefDo(byte[] data){
			aid = data;
		}

		public String toString(){
			return HexUtils.bin2hex(aid);
		}

		public byte getTag(){
			return AID_REF_DO;
		}

		public byte[] getData(){
			return aid;
		}
	}

	/**
	 * Hash-REF-DO (p46)
	 */
	public static class HashRefDo extends TLV {
		byte[] hash;

		public HashRefDo(byte[] data){
			hash = data;
		}

		public String toString(){
			return HexUtils.bin2hex(hash);
		}

		public byte getTag(){
			return HASH_REF_DO;
		}

		public byte[] getData(){
			return hash;
		}
	}

	/**
	 * AR-DO access rule data object (p47) composed of APDU-AR-DO or NFC-AR-DO or APDU-AR-DO | NFC-AR-DO
	 */
	public static class ArDo extends TLV {

		ApduArDo apduArDo;
		NfcArDo nfcArDo;

		public ArDo(ApduArDo apduArDo, NfcArDo nfcArDo){
			this.apduArDo = apduArDo;
			this.nfcArDo = nfcArDo;
		}

		public String toString(){
			return "apdu : " + apduArDo + " | nfc : " + nfcArDo;
		}

		public byte getTag(){
			return AR_DO;
		}

		public byte[] getData(){
			if (apduArDo != null && nfcArDo == null){
				return apduArDo.getBytes();
			}
			else if (apduArDo == null && nfcArDo != null){
				return nfcArDo.getBytes();
			}
			else {
				byte[] apduBytes = apduArDo.getBytes();
				byte[] nfcBytes = nfcArDo.getBytes();

				byte[] data = new byte[apduBytes.length + nfcBytes.length];
				System.arraycopy(apduBytes, 0, data, 0, apduBytes.length);
				System.arraycopy(nfcBytes, 0, data, apduBytes.length, nfcBytes.length);
				return data;
			}
		}
	}

	/**
	 * APDU-AR-DO access rule data object (p48).
	 */
	public static class ApduArDo extends TLV {

		EventAccessRules rule;
		byte[] filter;

		public ApduArDo(EventAccessRules rule, byte[] filter){
			this.rule = rule;
			this.filter = filter;
		}

		public ApduArDo(byte[] data){
			if (data.length == 0){
				switch(data[0]){
					case 0x00:
						this.rule = EventAccessRules.NEVER;
						break;
					case 0x01:
						this.rule = EventAccessRules.ALWAYS;
						break;
				}
			}
			else {
				this.rule = EventAccessRules.CUSTOM;
				this.filter = new byte[data.length];
				System.arraycopy(data, 0, this.filter, 0, data.length);
			}
		}

		public String toString(){
			return "rule : " + rule + " | filter : " + HexUtils.bin2hex(filter);
		}

		public byte getTag(){
			return APDU_AR_DO;
		}

		public byte[] getData(){
			if (enabled){
				if (rule == EventAccessRules.CUSTOM){
					return filter;
				}
				else{
					return new byte[]{rule.getValue()};
				}
			}
			else{
				//for delete data when disabling apdu & nfc is needed
				return new byte[]{};
			}
		}
	}

	/**
	 * NFC-AR-DO access rule data object.
	 */
	public static class NfcArDo extends TLV {

		EventAccessRules rule;

		public NfcArDo(EventAccessRules rule){
			this.rule = rule;
		}

		public String toString(){
			return "rule : " + rule;
		}

		public byte getTag(){
			return NFC_AR_DO;
		}

		public byte[] getData(){
			if (enabled){
				return new byte[]{rule.getValue()};
			}
			else{
				//for delete data when disabling apdu & nfc is needed
				return new byte[]{};
			}
		}
	}

	/**
	 * event access rule used by NFC-AR-DO and APDU-AR-DO (p48 + p49)
	 */
	enum EventAccessRules {
		NEVER((byte) 0x00),
		ALWAYS((byte) 0x01),
		CUSTOM((byte) 0x02);

		private byte value;

		private EventAccessRules(byte value) {
			this.value = value;
		}

		public byte getValue(){
			return value;
		}
	}

	public static class BerTlvData {
		/**
		 * data aggregated from the first get data request.
		 */
		private byte[] data;

		/**
		 * full data length .
		 */
		private int length;

		/**
		 * current processing index.
		 */
		private int currentIndex;

		public BerTlvData(byte[] data, int length, int index){
			this.data = data;
			this.length = length;
			this.currentIndex = index;
		}

		public void setCurrentIndex(int index){
			this.currentIndex = index;
		}

		public byte[] getData(){
			return data;
		}

		public int getLength(){
			return length;
		}

		public int getCurrentIndex(){
			return currentIndex;
		}
	}

	/**
	 * Parse access rule list response.
	 */
	public static class AcrListResponse {

		public List<RefArDo> acrList;

		public AcrListResponse(List<RefArDo> acrList) {
			this.acrList = acrList;
		}

		public static BerTlvData getAcrListData(BerTlvData previousData, byte[] data) throws GPDataException {

			if (previousData == null &&
					data.length > 2 &&
					(data[0] == ACR_GET_DATA_RESP[0]) &&
					(data[1] == ACR_GET_DATA_RESP[1])) {

				int first = data[2] & 0xFF; // fist byte determining length
				int length = 0; // actual length integer
				int offset = 3; //offset

				if (first < 0x80){
					length = first & 0xFF;
				}
				else {
					switch(first) {
						case 0x81:
							length = data[3] & 0xFF;
							offset++;
							break;
						case 0x82:
							length = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF);
							offset+=2;
							break;
						case 0x83:
							length = ((data[3] & 0xFF) << 16) | ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
							offset+=3;
							break;
						default:
							throw new GPDataException("ACR get data : bad BER TLV response format (GET_DATA)");
					}
				}
				byte[] berData = new byte[length];
				System.arraycopy(data, offset, berData, 0, data.length-offset);
				return new BerTlvData(berData, length, data.length - offset);
			}
			else if (previousData != null) {
				System.arraycopy(data, 0, previousData.getData(), previousData.currentIndex, data.length);
				previousData.setCurrentIndex(data.length + previousData.currentIndex);
				return previousData;
			}
			else {
				throw new GPDataException("ACR get data : bad response format (GET_DATA)");
			}
		}

		public static AcrListResponse fromBytes(int length, byte[] data) throws GPDataException {
			List<RefArDo> acrList = new ArrayList<>();

			int offset = 0;

			while (length > offset){
				acrList.add(parseRefArDo(Arrays.copyOfRange(data, offset, data.length)));
				offset += ((data[1 + offset] & 0xFF) + 2);
			}
			return new AcrListResponse(acrList);
		}
	}

	/**
	 * Parse REF_AR_DO object (p46 Secure Element Access Control v1.0).
	 *
	 * <p>
	 * 0xE2 | length | REF-DO | AR-DO
	 * </p>
	 *
	 * @param data REF_AR_DO data
	 * @return
	 * @throws GPDataException
	 */
	public static RefArDo parseRefArDo(byte[] data) throws GPDataException {
		if (data.length > 2 &&
				(data[0] == REF_AR_DO) &&
				((data[1] & 0xFF) <= (data.length-2))) {

			RefDo refDo = parseRefDo(Arrays.copyOfRange(data, 2, data.length));
			ArDo arDo = parseArDo(Arrays.copyOfRange(data, 2 + (2 + (data[3] & 0xFF)), data.length));

			return new RefArDo(refDo, arDo);
		}
		else {
			throw new GPDataException("ACR get data : bad response format (REF_AR_DO)");
		}
	}

	/**
	 * Parse REF_DO object (p46 Secure Element Access control v1.0).
	 *
	 * <p>
	 *	0xE1 | length | AID-REF-DO | Hash-REF-DO
	 * </p>
	 *
	 * @param data
	 * @return
	 * @throws GPDataException
	 */
	public static RefDo parseRefDo(byte[] data) throws GPDataException {
		if (data.length > 2 &&
				(data[0] == REF_DO) &&
				((data[1] & 0xFF) <= (data.length-2))) {

			AidRefDo aidRefDo = parseAidRefDo(Arrays.copyOfRange(data, 2, data.length));
			HashRefDo hashRefDo = parseHashRefDo(Arrays.copyOfRange(data, 2 + (2 + (data[3] & 0xFF)), data.length));

			return new RefDo(aidRefDo,hashRefDo);
		}
		else {
			throw new GPDataException("ACR get data : bad response format (REF_DO)");
		}
	}

	/**
	 * Parse AID_REF_DO object (p45 Secure Element Access Control v1.0).
	 *
	 * 4F | length | AID
	 *
	 * @param data
	 * @return
	 * @throws GPDataException
	 */
	public static AidRefDo parseAidRefDo(byte[] data) throws GPDataException{
		if (data.length > 2 &&
				(data[0] == AID_REF_DO) &&
				((data[1] & 0xFF) <= (data.length-2))) {
			return new AidRefDo(Arrays.copyOfRange(data, 2, (data[1]&0xFF)+2));
		}
		else {
			throw new GPDataException("ACR get data : bad response format (AID_REF_DO)");
		}
	}

	/**
	 * Parse HASH_REF_DO (p46 Secure Element Access Control v1.0).
	 *
	 * C1 | length | hash
	 *
	 * @param data
	 * @return
	 * @throws GPDataException
	 */
	public static HashRefDo parseHashRefDo(byte[] data) throws GPDataException{
		if (data.length > 2 &&
				(data[0] == HASH_REF_DO) &&
				((data[1] & 0xFF) <= (data.length-2)) &&
				((data[1] & 0xFF) == HASH_MAX_LENGTH || (data[1] & 0xFF) == HASH_MIN_LENGTH)) {
			return new HashRefDo(Arrays.copyOfRange(data, 2, (data[1]&0xFF)+2));
		}
		else {
			throw new GPDataException("ACR get data : bad response format (HASH_REF_DO)");
		}
	}

	/**
	 * Parse AR_DO (p47 Secure Element Access Control v1.0)
	 *
	 * E3 | length | APDU-AR-DO
	 *
	 * OR
	 *
	 * E3 | length | NFC-AR-DO
	 *
	 * OR
	 *
	 * E3 | length | APDU-AR-DO | NFC-AR-DO
	 *
	 * @param data
	 * @return
	 * @throws GPDataException
	 */
	public static ArDo parseArDo(byte[] data) throws GPDataException {
		if (data.length > 2 &&
				(data[0] == AR_DO) &&
				((data[1] & 0xFF) <= (data.length-2))) {

			ApduArDo apduArDo = null;
			NfcArDo nfcArDo = null;

			switch (data[2]){
				case APDU_AR_DO:
					apduArDo = parseApduArDo(Arrays.copyOfRange(data, 2, data.length));

					if ((data[1] & 0xFF) != ((data[3]&0xFF) + 2)){
						nfcArDo = parseNfcArDo(Arrays.copyOfRange(data, 2 + (2 + (data[3] & 0xFF)), data.length));
					}
					break;
				case NFC_AR_DO:
					nfcArDo = parseNfcArDo(Arrays.copyOfRange(data, 2, data.length));
					break;
			}
			return new ArDo(apduArDo,nfcArDo);
		}
		else {
			throw new GPDataException("ACR get data : bad response format (AR_DO)");
		}
	}

	/**
	 * Parse APDU_AR_DO (p48 Secure Element Access Control v1.0).
	 *
	 * D0 | length | 0x00 or 0x01 or APDU filter 1 | APDU filter n
	 *
	 * @param data
	 * @return
	 * @throws GPDataException
	 */
	public static ApduArDo parseApduArDo(byte[] data) throws GPDataException {
		if (data.length > 2 &&
				(data[0] == APDU_AR_DO) &&
				((data[1] & 0xFF) <= (data.length-2)) &&
				((data[1] & 0xFF) == 1 || (data[1] & 0xFF) % 8 == 0)) {

			if ((data[1] & 0xFF) == 1){
				switch (data[2] & 0xFF){
					case 0x01:
						return new ApduArDo(EventAccessRules.ALWAYS, new byte[]{});
					case 0x00:
						return new ApduArDo(EventAccessRules.NEVER, new byte[]{});
				}
			}
			else {
				return new ApduArDo(EventAccessRules.CUSTOM,Arrays.copyOfRange(data, 2, 2 + (data[1] & 0xFF)));
			}
		}
		else {
			throw new GPDataException("ACR get data : bad response format (APDU_AR_DO)");
		}
		return null;
	}

	/**
	 * Parse NFC_AR_DO (p49 Secure Element Access Control v1.0).
	 *
	 * D1 | 01 | 0x00 or 0x01
	 *
	 * @param data
	 * @return
	 * @throws GPDataException
	 */
	public static NfcArDo parseNfcArDo(byte[] data) throws GPDataException{
		if (data.length > 2 &&
				(data[0] == NFC_AR_DO) &&
				((data[1] & 0xFF) <= (data.length-2)) &&
				((data[1] & 0xFF) == 1)) {

			switch (data[2] & 0xFF){
				case 0x01:
					return new NfcArDo(EventAccessRules.ALWAYS);
				case 0x00:
					return new NfcArDo(EventAccessRules.NEVER);
			}
		}
		else {
			throw new GPDataException("ACR get data : bad response format (NFC_AR_DO)");
		}
		return null;
	}

	/**
	 * Print ACR list response.
	 *
	 * @param acrList list of REF-AR-DO
	 */
	public static void printList(List<RefArDo> acrList){
		if (acrList.size() == 0){
			System.out.println("No Rule found");
			return;
		}

		for (int i = 0; i < acrList.size();i++){
			System.out.println("RULE #" + i + " :");
			System.out.println("       AID  : " + acrList.get(i).refDo.aidRefDo);
			System.out.println("       HASH : " + acrList.get(i).refDo.hashRefDo);
			if (acrList.get(i).arDo.apduArDo != null){
				System.out.println("       APDU rule   : " + acrList.get(i).arDo.apduArDo.rule + "(" + String.format("0x%02X" , acrList.get(i).arDo.apduArDo.rule.getValue()) + ")");
				System.out.println("       APDU filter : " + HexUtils.bin2hex(acrList.get(i).arDo.apduArDo.filter));
			}
			if (acrList.get(i).arDo.nfcArDo != null){
				System.out.println("       NFC  rule   : " + acrList.get(i).arDo.nfcArDo.rule + "(" + String.format("0x%02X" , acrList.get(i).arDo.nfcArDo.rule.getValue()) + ")");
			}
		}
	}
}