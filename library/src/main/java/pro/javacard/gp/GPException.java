/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 * Copyright (C) 2014-2017 Martin Paljak, martin@martinpaljak.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package pro.javacard.gp;

import apdu4j.ResponseAPDU;

/**
 * Root exception class for all global platform protocol errors.
 */
@SuppressWarnings("serial")
public class GPException extends RuntimeException {

    /**
     * Response status indicating the error, or 0 if not applicable.
     */
    public final int sw;

    public GPException(int sw, String message) {
        super(message + ": " + GPData.sw2str(sw));
        this.sw = sw;
    }

    public GPException(String message) {
        super(message);
        this.sw = 0x0000;
    }

    public GPException(String message, Throwable e) {
        super(message, e);
        this.sw = 0x0000;
    }

    public static ResponseAPDU check(ResponseAPDU response, String message, int... sws) throws GPException {
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

    public static ResponseAPDU check(ResponseAPDU response) throws GPException {
        return check(response, "GlobalPlatform failed");
    }
}
