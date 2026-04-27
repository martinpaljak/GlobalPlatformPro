// SPDX-FileCopyrightText: 2015 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import apdu4j.core.HexUtils;

// Thrown when some data is not parseable for some reason, and includes the data in question.
public class GPDataException extends GPException {
    private static final long serialVersionUID = -4966789553820406244L;

    public GPDataException(final String message) {
        super(message);
    }

    public GPDataException(final String message, final Throwable e) {
        super(message, e);
    }

    public GPDataException(final String message, final byte[] data) {
        this(message + ": " + HexUtils.bin2hex(data));
    }
}
