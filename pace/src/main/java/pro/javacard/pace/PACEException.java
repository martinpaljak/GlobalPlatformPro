package pro.javacard.pace;

import apdu4j.core.ResponseAPDU;

public class PACEException extends Exception {

    private static final long serialVersionUID = 5273099422882172245L;

    public PACEException(final String message) {
        super(message);
    }

    public static ResponseAPDU check(final ResponseAPDU response) throws PACEException {
        if (response.getSW() == 0x6300) {
            throw new PACEException("Authentication failed");
        }
        return check(response, "Unexpected response");
    }

    public static ResponseAPDU check(final ResponseAPDU response, final String message) throws PACEException {
        if (response.getSW() == 0x9000) {
            return response;
        }
        throw new PACEException(message + ". Received " + SW(response.getSW()));
    }

    static String SW(final int sw) {
        return "%04X".formatted(sw);
    }
}
