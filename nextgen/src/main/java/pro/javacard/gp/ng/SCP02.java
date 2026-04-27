// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.core.BIBOSA;
import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
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

// SCP02 secure channel - hybrid DES/3DES MAC and encryption (GPC 2.3.1 E.5)
public final class SCP02 {

    private SCP02() {}

    public record State(byte[] encKey, byte[] macKey, byte[] rmacKey, byte[] icv,
                        EnumSet<GPSession.APDUMode> securityLevel,
                        byte[] sessionContext) implements SecureChannelState, AutoCloseable {

        public State(final byte[] encKey, final byte[] macKey, final byte[] rmacKey, final byte[] icv,
                     final EnumSet<GPSession.APDUMode> securityLevel) {
            this(encKey, macKey, rmacKey, icv, securityLevel, new byte[0]);
        }

        @Override
        public void close() {
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(macKey, (byte) 0);
            Arrays.fill(rmacKey, (byte) 0);
            Arrays.fill(icv, (byte) 0);
        }

        public State withContext(final byte[] ctx) {
            return new State(encKey, macKey, rmacKey, icv, securityLevel, ctx);
        }
    }

    public static BIBOSA secure(final BIBOSA stack, final State session) {
        final var mac = session.securityLevel.contains(GPSession.APDUMode.MAC);
        final var enc = session.securityLevel.contains(GPSession.APDUMode.ENC);
        final var rmac = session.securityLevel.contains(GPSession.APDUMode.RMAC);

        final var blockSize = stack.preferences().get(BLOCK_SIZE);
        final var transport = SecureChannels.withChaining(stack.bibo(), blockSize);
        final var stateful = new StatefulBIBO<>(transport, session,
                (cmd, s) -> wrap(cmd, s, mac, enc),
                (resp, s) -> unwrap(resp, s, rmac));

        var available = blockSize;
        if (mac) {
            available -= 8;
        }
        if (enc) {
            available = (available / 8) * 8 - 1;
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
                // Encrypt ICV with macKey before use
                final var encryptedIcv = GPCrypto.des_ecb(state.icv, state.macKey);

                cla |= 0x04;
                lc += 8;

                final var t = new ByteArrayOutputStream();
                t.write(cla);
                t.write(command.getINS());
                t.write(command.getP1());
                t.write(command.getP2());
                t.write(lc);
                t.writeBytes(data);

                // SCP02 uses hybrid DES/3DES MAC
                newIcv = GPCrypto.mac_des_3des(state.macKey, t.toByteArray(), encryptedIcv);
            }

            if (enc && data.length > 0) {
                newData = GPCrypto.des3_cbc(GPCrypto.pad80(data, 8), state.encKey, new byte[8]);
            }

            final var wrapped = SecureChannels.assembleAPDU(cla, command, newData, mac ? newIcv : null);
            return new Stateful<>(wrapped, new State(state.encKey, state.macKey, state.rmacKey, newIcv,
                    state.securityLevel, state.sessionContext));
        } catch (GeneralSecurityException e) {
            throw new GPException("APDU wrapping failed", e);
        }
    }

    private static Stateful<ResponseAPDU, State> unwrap(ResponseAPDU response, State state,
                                                        boolean rmac) {
        if (rmac) {
            if (response.getData().length < 8) {
                if (response.getSW() == 0x9000 || response.getSW1() == 0x62 || response.getSW1() == 0x63) {
                    throw new GPException("Received R-APDU without authentication data in RMAC session.");
                }
                return new Stateful<>(response, state);
            }
            final var respLen = response.getData().length - 8;
            final var actualMac = new byte[8];
            System.arraycopy(response.getData(), respLen, actualMac, 0, 8);

            final var bo = new ByteArrayOutputStream();
            bo.write(respLen);
            bo.write(response.getData(), 0, respLen);
            bo.write(response.getSW1());
            bo.write(response.getSW2());

            final var expectedMac = GPCrypto.mac_des_3des(state.rmacKey, GPCrypto.pad80(bo.toByteArray(), 8), state.icv);
            if (!Arrays.equals(expectedMac, actualMac)) {
                throw new GPException("RMAC invalid: " + HexUtils.bin2hex(actualMac)
                        + " vs " + HexUtils.bin2hex(expectedMac));
            }

            final var o = new ByteArrayOutputStream();
            o.write(response.getData(), 0, respLen);
            o.write(response.getSW1());
            o.write(response.getSW2());
            response = new ResponseAPDU(o.toByteArray());
        }
        return new Stateful<>(response, state);
    }
}
