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
import pro.javacard.gp.GPUtils;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.EnumSet;

import static pro.javacard.gp.ng.GlobalPlatformCookbook.BLOCK_SIZE;
import static pro.javacard.gp.ng.GlobalPlatformCookbook.SCP03_BUGGY_COUNTER;

// SCP03 secure channel - AES-CMAC and AES-CBC encryption (GPC Amendment D)
public final class SCP03 {

    private SCP03() {}

    public record State(byte[] encKey, byte[] macKey, byte[] rmacKey, byte[] chainingValue,
                        EnumSet<GPSession.APDUMode> securityLevel, boolean s16,
                        byte[] sessionContext, long counter) implements SecureChannelState, AutoCloseable {

        public State(final byte[] encKey, final byte[] macKey, final byte[] rmacKey, final byte[] chainingValue,
                     final EnumSet<GPSession.APDUMode> securityLevel, final boolean s16) {
            this(encKey, macKey, rmacKey, chainingValue, securityLevel, s16, new byte[0], 0);
        }

        @Override
        public void close() {
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(macKey, (byte) 0);
            Arrays.fill(rmacKey, (byte) 0);
            Arrays.fill(chainingValue, (byte) 0);
        }

        public State withContext(final byte[] ctx) {
            return new State(encKey, macKey, rmacKey, chainingValue, securityLevel, s16, ctx, counter);
        }
    }

    public static BIBOSA secure(final BIBOSA stack, final State session) {
        final var mac = session.securityLevel.contains(GPSession.APDUMode.MAC);
        final var enc = session.securityLevel.contains(GPSession.APDUMode.ENC);
        final var rmac = session.securityLevel.contains(GPSession.APDUMode.RMAC);
        final var renc = session.securityLevel.contains(GPSession.APDUMode.RENC);
        final var buggyCounter = stack.preferences().get(SCP03_BUGGY_COUNTER);

        final var blockSize = stack.preferences().get(BLOCK_SIZE);
        final var transport = SecureChannels.withChaining(stack.bibo(), blockSize);
        final var stateful = new StatefulBIBO<>(transport, session,
                (cmd, s) -> wrap(cmd, s, mac, enc, buggyCounter),
                (resp, s) -> unwrap(resp, s, rmac, renc));

        final var maclen = session.s16 ? 16 : 8;
        var available = blockSize;
        if (mac) {
            available -= maclen;
        }
        if (enc) {
            available = (available / 16) * 16 - 1;
        }
        return new BIBOSA(stateful, stack.preferences().with(BLOCK_SIZE, available));
    }

    private static Stateful<CommandAPDU, State> wrap(final CommandAPDU command, final State state,
                                                     final boolean mac, final boolean enc,
                                                     final boolean buggyCounter) {
        try {
            final var maclen = state.s16 ? 16 : 8;
            var cla = command.getCLA();
            var lc = command.getNc();
            var data = command.getData();
            byte[] cmdMac = null;
            var newCounter = state.counter;
            final var newChainingValue = state.chainingValue.clone();

            if (enc) {
                cla |= 0x04;
                // GP 2.2 Amendment D v1.1.1 section 6.2.6
                if (!buggyCounter || data.length > 0) {
                    newCounter++;
                }
                if (data.length > 0) {
                    final var padded = GPCrypto.pad80(data, 16);
                    final var iv = GPCrypto.aes_cbc(counterize(newCounter), state.encKey, new byte[16]);
                    data = GPCrypto.aes_cbc(padded, state.encKey, iv);
                    lc = data.length;
                }
            }

            if (mac) {
                cla |= 0x04;
                lc += maclen;

                final var bo = new ByteArrayOutputStream();
                bo.writeBytes(newChainingValue);
                bo.write(cla);
                bo.write(command.getINS());
                bo.write(command.getP1());
                bo.write(command.getP2());
                bo.writeBytes(GPUtils.encodeLcLength(lc, command.getNe()));
                bo.writeBytes(data);

                final var cmac = GPCrypto.aes_cmac(state.macKey, bo.toByteArray(), 128);
                System.arraycopy(cmac, 0, newChainingValue, 0, 16);
                cmdMac = Arrays.copyOf(cmac, maclen);
            }

            final var wrapped = SecureChannels.assembleAPDU(cla, command, data, cmdMac);
            return new Stateful<>(wrapped, new State(state.encKey, state.macKey, state.rmacKey,
                    newChainingValue, state.securityLevel, state.s16, state.sessionContext, newCounter));
        } catch (GeneralSecurityException e) {
            throw new GPException("APDU wrapping failed", e);
        }
    }

    private static Stateful<ResponseAPDU, State> unwrap(ResponseAPDU response, State state,
                                                        boolean rmac, boolean renc) {
        try {
            final var maclen = state.s16 ? 16 : 8;

            if (rmac) {
                if (response.getData().length < maclen) {
                    if (response.getSW() == 0x9000 || response.getSW1() == 0x62 || response.getSW1() == 0x63) {
                        throw new GPException("Received R-APDU without authentication data in RMAC session.");
                    }
                    return new Stateful<>(response, state);
                }
                final var respLen = response.getData().length - maclen;

                final var actualMac = new byte[maclen];
                System.arraycopy(response.getData(), respLen, actualMac, 0, maclen);

                final var bo = new ByteArrayOutputStream();
                bo.writeBytes(state.chainingValue);
                bo.write(response.getData(), 0, respLen);
                bo.write(response.getSW1());
                bo.write(response.getSW2());

                final var cmac = GPCrypto.aes_cmac(state.rmacKey, bo.toByteArray(), 128);
                final var expectedMac = Arrays.copyOf(cmac, maclen);

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

            if (renc && response.getData().length > 0) {
                final var responseCounter = counterize(state.counter);
                responseCounter[0] = (byte) 0x80;
                final var iv = GPCrypto.aes_cbc(responseCounter, state.encKey, new byte[16]);
                final var decrypted = GPCrypto.aes_cbc_decrypt(response.getData(), state.encKey, iv);
                final var unpadded = GPCrypto.unpad80(decrypted);

                final var o = new ByteArrayOutputStream();
                o.writeBytes(unpadded);
                o.write(response.getSW1());
                o.write(response.getSW2());
                response = new ResponseAPDU(o.toByteArray());
            }

            return new Stateful<>(response, state);
        } catch (GeneralSecurityException e) {
            throw new GPException("APDU unwrapping failed", e);
        }
    }

    private static byte[] counterize(final long counter) {
        final var buf = new byte[16];
        ByteBuffer.wrap(buf, 8, 8).putLong(counter);
        return buf;
    }
}
