/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2018 Martin Paljak, martin@martinpaljak.net
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
 */
package pro.javacard.gp;

import apdu4j.CommandAPDU;
import apdu4j.HexUtils;
import apdu4j.ResponseAPDU;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.EnumSet;

import static pro.javacard.gp.GPCardKeys.KeyPurpose.*;

// SCP02 15 - CMAC on modified APDU, ICV zero, ICV encryption, no RMAC (55 = well-known random)
class SCP02Wrapper extends SecureChannelWrapper {
    private static final Logger logger = LoggerFactory.getLogger(SCP02Wrapper.class);

    private final ByteArrayOutputStream rMac = new ByteArrayOutputStream();
    private byte[] icv = null;
    private byte[] ricv = null;

    private boolean icvEnc = false;
    private boolean macModifiedAPDU = false;
    private boolean postAPDU = false;


    SCP02Wrapper(GPSessionKeys sessionKeys, EnumSet<GPSession.APDUMode> securityLevel, int bs) {
        super(sessionKeys, securityLevel, bs);
        setVariant(0x55);
    }

    private static byte clearBits(byte b, byte mask) {
        return (byte) ((b & ~mask) & 0xFF);
    }

    private static byte setBits(byte b, byte mask) {
        return (byte) ((b | mask) & 0xFF);
    }

    public void setVariant(int i) {
        icvEnc = true;
        macModifiedAPDU = true;
    }

    public CommandAPDU wrap(CommandAPDU command) throws GPException {

        try {
            if (rmac) {
                rMac.reset();
                rMac.write(clearBits((byte) command.getCLA(), (byte) 0x07));
                rMac.write(command.getINS());
                rMac.write(command.getP1());
                rMac.write(command.getP2());
                if (command.getNc() >= 0) {
                    rMac.write(command.getNc());
                    rMac.write(command.getData());
                }
            }
            if (!mac && !enc) {
                return command;
            }


            int origCLA = command.getCLA();
            int newCLA = origCLA;
            int origINS = command.getINS();
            int origP1 = command.getP1();
            int origP2 = command.getP2();
            byte[] origData = command.getData();
            int origLc = command.getNc();
            int newLc = origLc;
            byte[] newData = null;
            int le = command.getNe();
            ByteArrayOutputStream t = new ByteArrayOutputStream();

            if (origLc > getBlockSize()) {
                throw new IllegalArgumentException("APDU too long for wrapping.");
            }

            if (mac) {
                // This conditional is hard to read, but external update ICV MUST be always 0 and this assures it.
                if (icv == null) {
                    icv = new byte[8];
                } else if (icvEnc) {
                    byte[] key = sessionKeys.get(MAC);
                    Cipher c = Cipher.getInstance(GPCrypto.DES_ECB_CIPHER);
                    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(GPCrypto.resizeDES(key, 8), "DES"));
                    // encrypts the future ICV ?
                    icv = c.doFinal(icv);
                }

                if (macModifiedAPDU) {
                    newCLA = setBits((byte) newCLA, (byte) 0x04);
                    newLc = newLc + 8;
                }
                t.write(newCLA);
                t.write(origINS);
                t.write(origP1);
                t.write(origP2);
                t.write(newLc);
                t.write(origData);


                logger.debug("MAC input: {}", HexUtils.bin2hex(t.toByteArray()));
                icv = GPCrypto.mac_des_3des(sessionKeys.get(MAC), t.toByteArray(), icv);

                if (postAPDU) {
                    newCLA = setBits((byte) newCLA, (byte) 0x04);
                    newLc = newLc + 8;
                }
                t.reset();
                newData = origData;
            }

            if (enc && (origLc > 0)) {
                t.write(GPCrypto.pad80(origData, 8));
                newLc += t.size() - origData.length;

                Cipher c = Cipher.getInstance(GPCrypto.DES3_CBC_CIPHER);
                c.init(Cipher.ENCRYPT_MODE, GPCrypto.des3key(sessionKeys.get(ENC)), GPCrypto.iv_null_8);
                newData = c.doFinal(t.toByteArray());
                t.reset();
            }

            // Construct new APDU
            t.write(newCLA);
            t.write(origINS);
            t.write(origP1);
            t.write(origP2);
            if (newLc > 0) {
                t.write(newLc);
                t.write(newData);
            }
            if (mac) {
                t.write(icv);
            }
            if (le > 0) {
                t.write(le);
            }
            CommandAPDU wrapped = new CommandAPDU(t.toByteArray());
            return wrapped;
        } catch (IOException e) {
            throw new RuntimeException("APDU wrapping failed", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("APDU wrapping failed", e);
        } catch (GeneralSecurityException e) {
            throw new GPException("APDU wrapping failed", e);
        }
    }

    public ResponseAPDU unwrap(ResponseAPDU response) throws GPException {
        if (rmac) {
            if (response.getData().length < 8) {
                throw new GPException("Wrong response length (too short).");
            }
            int respLen = response.getData().length - 8;
            rMac.write(respLen);
            rMac.write(response.getData(), 0, respLen);
            rMac.write(response.getSW1());
            rMac.write(response.getSW2());

            ricv = GPCrypto.mac_des_3des(sessionKeys.get(RMAC), GPCrypto.pad80(rMac.toByteArray(), 8), ricv);

            byte[] actualMac = new byte[8];
            System.arraycopy(response.getData(), respLen, actualMac, 0, 8);
            if (!Arrays.equals(ricv, actualMac)) {
                throw new GPException("RMAC invalid.");
            }
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            o.write(response.getBytes(), 0, respLen);
            o.write(response.getSW1());
            o.write(response.getSW2());
            response = new ResponseAPDU(o.toByteArray());
        }
        return response;
    }
}
