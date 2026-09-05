// SPDX-FileCopyrightText: 2015 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

// SCP02 - CMAC on modified APDU, ICV zero, ICV encryption, no RMAC
class SCP02Wrapper extends SecureChannelWrapper {
    private static final Logger logger = LoggerFactory.getLogger(SCP02Wrapper.class);

    private final ByteArrayOutputStream rMac = new ByteArrayOutputStream();
    private byte[] icv = null;
    private byte[] ricv = null;

    SCP02Wrapper(final byte[] enc, final byte[] mac, final byte[] rmacKey, final int bs) {
        super(enc, mac, rmacKey, bs);
    }

    private static byte clearBits(final byte b, final byte mask) {
        return (byte) ((b & ~mask) & 0xFF);
    }

    private static byte setBits(final byte b, final byte mask) {
        return (byte) ((b | mask) & 0xFF);
    }

    @Override
    public CommandAPDU wrap(final CommandAPDU command) throws GPException {

        try {
            if (rmac) {
                rMac.reset();
                rMac.write(clearBits((byte) command.getCLA(), (byte) 0x07));
                rMac.write(command.getINS());
                rMac.write(command.getP1());
                rMac.write(command.getP2());
                if (command.getNc() >= 0) {
                    rMac.write(command.getNc());
                    rMac.writeBytes(command.getData());
                }
            }

            if (!mac && !enc) {
                return command;
            }

            final var origCLA = command.getCLA();
            var newCLA = origCLA;
            final var origINS = command.getINS();
            final var origP1 = command.getP1();
            final var origP2 = command.getP2();
            final var origData = command.getData();
            final var origLc = command.getNc();
            var newLc = origLc;
            byte[] newData = null;
            final var le = command.getNe();
            final var t = new ByteArrayOutputStream();

            if (origLc > getBlockSize()) {
                throw new IllegalArgumentException("APDU too long for wrapping.");
            }

            if (mac) {
                // This conditional is hard to read, but external update ICV MUST be always 0 and this assures it.
                if (icv == null) {
                    icv = new byte[8];
                } else {
                    icv = GPCrypto.des_ecb(icv, macKey);
                }

                newCLA = setBits((byte) newCLA, (byte) 0x04);
                newLc = newLc + 8;
                t.write(newCLA);
                t.write(origINS);
                t.write(origP1);
                t.write(origP2);
                t.write(newLc);
                t.writeBytes(origData);

                logger.trace("MAC input: {}", HexUtils.bin2hex(t.toByteArray()));
                icv = GPCrypto.mac_des_3des(macKey, t.toByteArray(), icv);

                t.reset();
                newData = origData;
            }

            if (enc && (origLc > 0)) {
                t.writeBytes(GPCrypto.pad80(origData, 8));
                newLc += t.size() - origData.length;

                newData = GPCrypto.des3_cbc(t.toByteArray(), encKey, new byte[8]);
                t.reset();
            }

            // Construct new APDU
            t.write(newCLA);
            t.write(origINS);
            t.write(origP1);
            t.write(origP2);
            if (newLc > 0) {
                t.write(newLc); // XXX: extended length
                t.writeBytes(newData);
            }
            if (mac) {
                t.writeBytes(icv);
            }
            if (le > 0) {
                t.write(le);
            }
            final var wrapped = new CommandAPDU(t.toByteArray());
            return wrapped;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("APDU wrapping failed", e);
        } catch (GeneralSecurityException e) {
            throw new GPException("APDU wrapping failed", e);
        }
    }

    @Override
    public ResponseAPDU unwrap(ResponseAPDU response) throws GPException {
        if (rmac) {
            if (response.getData().length < 8) {
                throw new GPException("Wrong response length (too short).");
            }
            final var respLen = response.getData().length - 8;
            rMac.write(respLen);
            rMac.write(response.getData(), 0, respLen);
            rMac.write(response.getSW1());
            rMac.write(response.getSW2());

            ricv = GPCrypto.mac_des_3des(rmacKey, GPCrypto.pad80(rMac.toByteArray(), 8), ricv);

            final byte[] actualMac = new byte[8];
            System.arraycopy(response.getData(), respLen, actualMac, 0, 8);
            if (!Arrays.equals(ricv, actualMac)) {
                throw new GPException("RMAC invalid.");
            }
            final var o = new ByteArrayOutputStream();
            o.write(response.getBytes(), 0, respLen);
            o.write(response.getSW1());
            o.write(response.getSW2());
            response = new ResponseAPDU(o.toByteArray());
        }
        return response;
    }
}
