// SPDX-FileCopyrightText: 2012 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2009 Wojciech Mostowski <woj@cs.ru.nl>
// SPDX-FileCopyrightText: 2009 Francois Kooman <F.Kooman@student.science.ru.nl>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import apdu4j.core.ResponseAPDU;

/**
 * Root exception class for all global platform protocol errors.
 */
public class GPException extends RuntimeException {
    private static final long serialVersionUID = 4446501507584168733L;
    /**
     * Response status indicating the error, or 0 if not applicable.
     */
    public final int sw;

    public GPException(final int sw, final String message) {
        super(message + ": " + GPData.sw2str(sw));
        this.sw = sw;
    }

    public GPException(final String message) {
        super(message);
        this.sw = 0x0000;
    }

    public GPException(final String message, final Throwable e) {
        super(message, e);
        this.sw = 0x0000;
    }

    public static ResponseAPDU check(final ResponseAPDU response, final String message, final int... sws) throws GPException {
        for (int sw : sws) {
            if (response.getSW() == sw) {
                return response;
            }
        }
        // Fallback
        if (response.getSW() == 0x9000) {
            return response;
        }

        throw new GPException(response.getSW(), message);
    }

    public static ResponseAPDU check(final ResponseAPDU response) throws GPException {
        return check(response, "GlobalPlatform failed");
    }
}
