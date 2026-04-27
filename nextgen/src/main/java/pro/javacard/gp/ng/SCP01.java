// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.core.BIBOSA;
import apdu4j.core.CommandAPDU;
import apdu4j.core.Stateful;
import apdu4j.core.StatefulBIBO;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPSession;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.EnumSet;

import static pro.javacard.gp.ng.GlobalPlatformCookbook.BLOCK_SIZE;

// SCP01 secure channel - 3DES MAC and encryption (GPC 2.3.1 E.5)
public final class SCP01 {

    private SCP01() {}

    public record State(byte[] encKey, byte[] macKey, byte[] icv,
                        EnumSet<GPSession.APDUMode> securityLevel,
                        byte[] sessionContext) implements SecureChannelState, AutoCloseable {

        public State(final byte[] encKey, final byte[] macKey, final byte[] icv, final EnumSet<GPSession.APDUMode> securityLevel) {
            this(encKey, macKey, icv, securityLevel, new byte[0]);
        }

        @Override
        public void close() {
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(macKey, (byte) 0);
            Arrays.fill(icv, (byte) 0);
        }

        public State withContext(final byte[] ctx) {
            return new State(encKey, macKey, icv, securityLevel, ctx);
        }
    }

    public static BIBOSA secure(final BIBOSA stack, final State session) {
        final var mac = session.securityLevel.contains(GPSession.APDUMode.MAC);
        final var enc = session.securityLevel.contains(GPSession.APDUMode.ENC);

        final var blockSize = stack.preferences().get(BLOCK_SIZE);
        final var transport = SecureChannels.withChaining(stack.bibo(), blockSize);
        final var stateful = new StatefulBIBO<>(transport, session,
                (cmd, s) -> wrap(cmd, s, mac, enc),
                (resp, s) -> new Stateful<>(resp, s));

        var available = blockSize;
        if (mac) {
            available -= 8;
        }
        if (enc) {
            available = (available / 8) * 8 - 2;
        }
        return new BIBOSA(stateful, stack.preferences().with(BLOCK_SIZE, available));
    }

    private static Stateful<CommandAPDU, State> wrap(final CommandAPDU command, final State state,
                                                     final boolean mac, final boolean enc) {
        try {
            var cla = command.getCLA();
            final var data = command.getData();
            var lc = command.getNc();
            var newData = data;
            var newIcv = state.icv;

            if (mac) {
                cla |= 0x04;
                lc += 8;

                final var t = new ByteArrayOutputStream();
                t.write(cla);
                t.write(command.getINS());
                t.write(command.getP1());
                t.write(command.getP2());
                t.write(lc);
                t.writeBytes(data);

                // SCP01 uses full 3DES MAC
                newIcv = GPCrypto.mac_3des(t.toByteArray(), state.macKey, state.icv);
            }

            if (enc && data.length > 0) {
                // SCP01 encryption: prepend length, pad, encrypt
                final var t = new ByteArrayOutputStream();
                t.write(data.length);
                t.writeBytes(data);
                final var padded = GPCrypto.pad80(t.toByteArray(), 8);
                newData = GPCrypto.des3_cbc(padded, state.encKey, new byte[8]);
            }

            final var wrapped = SecureChannels.assembleAPDU(cla, command, newData, mac ? newIcv : null);
            return new Stateful<>(wrapped, new State(state.encKey, state.macKey, newIcv,
                    state.securityLevel, state.sessionContext));
        } catch (GeneralSecurityException e) {
            throw new GPException("APDU wrapping failed", e);
        }
    }
}
