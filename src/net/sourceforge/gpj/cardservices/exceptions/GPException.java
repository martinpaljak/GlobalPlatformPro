/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
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

package net.sourceforge.gpj.cardservices.exceptions;

import javax.smartcardio.CardException;

/**
 * 
 * Root exception class for all global platform protocol errors.
 */
public class GPException extends CardException {

    /**
     * 
     * Field to disable the serialVersionUID warning.
     */
    public static final long serialVersionUID = 1L;

    /**
     * 
     * Response status indicating the error, or 0 if not applicable.
     */
    public final short sw;

    /**
     * 
     * Constructs a new GPException with the specified detail message.
     * 
     * @param sw
     *            failing response status
     * @param message
     *            the detailed message
     */
    public GPException(short sw, String message) {
        super(message);
        this.sw = sw;
    }

    /**
     * 
     * Constructs a new GPException with the specified detail message and cause.
     * 
     * @param sw
     *            failing response status
     * @param message
     *            the detailed message
     * @param cause
     *            the cause of this exception or null
     */
    public GPException(short sw, String message, Throwable cause) {
        super(message, cause);
        this.sw = sw;
    }

    /**
     * 
     * Constructs a new GPException with the specified cause and a detail
     * message of {@code (cause==null ? null : cause.toString())}.
     * 
     * @param cause
     *            the cause of this exception or null
     */
    public GPException(Throwable cause) {
        super(cause);
        sw = 0;
    }
}
