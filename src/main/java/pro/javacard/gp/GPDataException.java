package pro.javacard.gp;

import apdu4j.HexUtils;

@SuppressWarnings("serial")
public class GPDataException extends GPException {

	public GPDataException(String message) {
		super(message);
	}

	public GPDataException(String message, Throwable e) {
		super(message, e);
	}

	public GPDataException(String message, byte[] data) {
		this(message + ": " + HexUtils.bin2hex(data));
	}
}
