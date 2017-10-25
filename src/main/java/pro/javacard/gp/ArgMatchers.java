package pro.javacard.gp;

import apdu4j.HexUtils;
import joptsimple.ValueConversionException;
import joptsimple.ValueConverter;
import pro.javacard.gp.GPKey.Type;
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
					return new GPKey(HexUtils.hex2bin(arg0));
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
