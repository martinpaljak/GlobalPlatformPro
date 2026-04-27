// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

// Thrown when byte data cannot be parsed as valid TLV
public class TLVParseException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    public TLVParseException(final String message) {
        super(message);
    }

    public TLVParseException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
