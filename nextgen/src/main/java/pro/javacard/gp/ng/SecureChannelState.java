// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

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
