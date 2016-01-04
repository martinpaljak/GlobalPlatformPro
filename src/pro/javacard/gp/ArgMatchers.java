package pro.javacard.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import apdu4j.HexUtils;
import joptsimple.ValueConversionException;
import joptsimple.ValueConverter;
import pro.javacard.gp.GPKeySet.Diversification;
import pro.javacard.gp.GPKeySet.GPKey;
import pro.javacard.gp.GPKeySet.GPKey.Type;
import pro.javacard.gp.GlobalPlatform.APDUMode;

public class ArgMatchers {
	private static Logger logger = LoggerFactory.getLogger(ArgMatchers.class);

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
					return new GPKey(HexUtils.decodeHexString(s.substring("aes:".length())), Type.AES);
				} else if (s.startsWith("des:")) {
					return new GPKey(HexUtils.decodeHexString(s.substring("des:".length())), Type.DES3);
				} else {
					// FIXME: not rally nice to fall back to 3DES, but works for 90% of usecases.
					return new GPKey(HexUtils.decodeHexString(arg0), Type.DES3);
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

	public static ValueConverter<GPKeySet> keyset() {
		return new KeySetMatcher();
	}

	public static class KeySetMatcher implements ValueConverter<GPKeySet> {

		@Override
		public Class<GPKeySet> valueType() {
			return GPKeySet.class;
		}

		@Override
		public String valuePattern() {
			return null;
		}

		@Override
		public GPKeySet convert(String arg0) {
			try {
				GPKey m = null;
				Diversification d = Diversification.NONE;
				// Check if diversification is necessary
				String in = arg0.trim().toUpperCase();
				if (in.startsWith("EMV:")) {
					m = new GPKey(HexUtils.decodeHexString(in.substring("EMV:".length())), Type.DES3);
					d = Diversification.EMV;
				} else if (in.startsWith("VISA2:")) {
					m = new GPKey(HexUtils.decodeHexString(in.substring("VISA2:".length())), Type.DES3);
					d = Diversification.VISA2;
				} else if (in.startsWith("AES:")) {
					m = new GPKey(HexUtils.decodeHexString(in.substring("AES:".length())), Type.AES);
				} else {
					m = new GPKey(HexUtils.decodeHexString(in), Type.DES3);
				}
				GPKeySet ks = new GPKeySet(m);
				ks.suggestedDiversification = d;
				logger.debug(ks.toString());
				return ks;
			} catch (IllegalArgumentException e) {
				throw new ValueConversionException(arg0 + " is not a valid keyset indicator!");
			}
		}
	}
}
