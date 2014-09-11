package openkms.gp;

import joptsimple.ValueConversionException;
import joptsimple.ValueConverter;
import openkms.gp.GlobalPlatform.APDUMode;
import openkms.gp.KeySet.Key;

import java.math.BigInteger;

public class GPToolArgumentMatchers {

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

	public static ValueConverter<Key> key() {
		return new KeyMatcher();
	}

	public static class KeyMatcher implements ValueConverter<Key> {

		@Override
		public Class<Key> valueType() {
			return Key.class;
		}

		@Override
		public String valuePattern() {
			return null;
		}

		@Override
		public Key convert(String arg0) {
			try {
				return new Key(arg0);
			} catch (IllegalArgumentException e) {
				throw new ValueConversionException(arg0 + " is not a valid 3DES key!");
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

    public static ValueConverter<InstallParams> installParams() {
        return new InstallParamMatcher();
    }

    public static class InstallParamMatcher implements ValueConverter<InstallParams> {

        @Override
        public Class<InstallParams> valueType() {
            return InstallParams.class;
        }

        @Override
        public String valuePattern() {
            return null;
        }

        @Override
        public InstallParams convert(String hex) {
            try {
                return new InstallParams(hex);
            } catch (IllegalArgumentException e) {
                throw new ValueConversionException(hex + " is not an hex-encoded byte array!");
            }
        }
    }
}
