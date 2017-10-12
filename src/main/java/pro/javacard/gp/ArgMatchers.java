package pro.javacard.gp;

import apdu4j.HexUtils;
import joptsimple.ValueConversionException;
import joptsimple.ValueConverter;
import pro.javacard.gp.GPKeySet.Diversification;
import pro.javacard.gp.GPKeySet.GPKey;
import pro.javacard.gp.GPKeySet.GPKey.Type;
import pro.javacard.gp.GlobalPlatform.APDUMode;

public class ArgMatchers {

	public static ValueConverter<AID> aid() {
		return new AIDMatcher();
	}

	public static class AIDMatcher implements ValueConverter<AID> {

		@Override
		public Class<AID> valueType() {
			return AID.class;
		}

		@Override
		public String valuePattern() {
			return null;
		}

		@Override
		public AID convert(String arg0) {
			try {
				return new AID(arg0);
			} catch (IllegalArgumentException e) {
				throw new ValueConversionException(arg0 + " is not a valid AID!");
			}
		}
	}

	public static ValueConverter<GPKey> key() {
		return new KeyMatcher();
	}

	public static class KeyMatcher implements ValueConverter<GPKey> {

		@Override
		public Class<GPKey> valueType() {
			return GPKey.class;
		}

		@Override
		public String valuePattern() {
			return null;
		}

		@Override
		public GPKey convert(String arg0) {
			try {
				String s = arg0.toLowerCase();
				if (s.startsWith("aes:")) {
					return new GPKey(HexUtils.hex2bin(s.substring("aes:".length())), Type.AES);
				} else if (s.startsWith("3des:")) {
					return new GPKey(HexUtils.hex2bin(s.substring("3des:".length())), Type.DES3);
				} else {
					// XXX: not rally nice to fall back to 3DES, but works for 90% of usecases.
					return new GPKey(HexUtils.hex2bin(arg0), Type.DES3);
				}
			} catch (IllegalArgumentException e) {
				throw new ValueConversionException(arg0 + " is not a valid key!");
			}
		}
	}

	public static ValueConverter<APDUMode> mode() {
		return new APDUModeMatcher();
	}

	public static class APDUModeMatcher implements ValueConverter<APDUMode> {

		@Override
		public Class<APDUMode> valueType() {
			return APDUMode.class;
		}

		@Override
		public String valuePattern() {
			return null;
		}

		@Override
		public APDUMode convert(String arg0) {
			try {
				return APDUMode.valueOf(arg0.trim().toUpperCase());
			} catch (IllegalArgumentException e) {
				throw new ValueConversionException(arg0 + " is not an APDU mode!");
			}
		}
	}

	public static ValueConverter<PlaintextKeys> keyset() {
		return new KeySetMatcher();
	}

	public static class KeySetMatcher implements ValueConverter<PlaintextKeys> {

		@Override
		public Class<PlaintextKeys> valueType() {
			return PlaintextKeys.class;
		}

		@Override
		public String valuePattern() {
			return null;
		}

		@Override
		public PlaintextKeys convert(String arg0) {
			try {
				GPKey m = null;
				Diversification d = Diversification.NONE;
				// Check if diversification is necessary
				String in = arg0.trim().toLowerCase();
				if (in.startsWith("emv:")) {
					m = new GPKey(HexUtils.hex2bin(in.substring("emv:".length())), Type.DES3);
					d = Diversification.EMV;
				} else if (in.startsWith("visa2:")) {
					m = new GPKey(HexUtils.hex2bin(in.substring("visa2:".length())), Type.DES3);
					d = Diversification.VISA2;
				} else if (in.startsWith("aes:")) {
					m = new GPKey(HexUtils.hex2bin(in.substring("aes:".length())), Type.AES);
				} else {
					m = new GPKey(HexUtils.hex2bin(in), Type.DES3);
				}
				return PlaintextKeys.fromMasterKey(m, d);
			} catch (IllegalArgumentException e) {
				throw new ValueConversionException(arg0 + " is not a valid master key indicator!");
			}
		}
	}

	public static ValueConverter<byte []> hex() {
		return new HexStringMatcher();
	}

	public static class HexStringMatcher implements ValueConverter<byte []> {

		@Override
		public Class<byte []> valueType() {
			return byte[].class;
		}

		@Override
		public String valuePattern() {
			return null;
		}

		@Override
		public byte[] convert(String arg0) {
			try {
				return HexUtils.stringToBin(arg0);
			} catch (IllegalArgumentException e) {
				throw new ValueConversionException(arg0 + " is not a valid hex string!");
			}
		}
	}
}
