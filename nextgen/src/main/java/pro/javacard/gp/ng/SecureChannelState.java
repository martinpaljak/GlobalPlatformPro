/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2026-present Martin Paljak, martin@martinpaljak.net
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
package pro.javacard.gp.ng;

import apdu4j.core.BIBOSA;

// Pure data - session state produced by open_secure_channel recipe
public sealed interface SecureChannelState permits SCP01.State, SCP02.State, SCP03.State {
    byte[] sessionContext();

    static BIBOSA secure(BIBOSA stack, SecureChannelState state) {
        return switch (state) {
            case SCP01.State s -> SCP01.secure(stack, s);
            case SCP02.State s -> SCP02.secure(stack, s);
            case SCP03.State s -> SCP03.secure(stack, s);
        };
    }
}
