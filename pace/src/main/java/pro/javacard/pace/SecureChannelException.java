package pro.javacard.pace;

import apdu4j.core.ResponseAPDU;

public class SecureChannelException extends RuntimeException {

    private static final long serialVersionUID = -9061244282788985607L;

    public SecureChannelException(String message) {
        super(message);
    }

    public static ResponseAPDU check(ResponseAPDU response) throws SecureChannelException {
        return check(response, "Unexpected response");
    }

    public static ResponseAPDU check(ResponseAPDU response, String message) throws SecureChannelException {
        if (response.getSW() == 0x9000) {
            return response;
        }
        throw new SecureChannelException(message + ". Received " + SW(response.getSW()));
    }

    static String SW(int sw) {
        return String.format("%04X", sw).toUpperCase();
    }
}
