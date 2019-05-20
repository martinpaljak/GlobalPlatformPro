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
import apdu4j.ResponseAPDU;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;

import static pro.javacard.gp.GPCardKeys.KeyPurpose.*;

// SCP01 05 - no ICV encryption 15 - ICV encryption (
class SCP01Wrapper extends SecureChannelWrapper {
    private boolean icvEnc = false;
    private boolean preAPDU = true;
    private boolean postAPDU = false;

    byte[] icv = null;

    SCP01Wrapper(GPSessionKeys sessionKeys, EnumSet<GPSession.APDUMode> securityLevel, int bs) {
        super(sessionKeys, securityLevel, bs);
        setVariant(0x15);
    }

    private static byte setBits(byte b, byte mask) {
        return (byte) ((b | mask) & 0xFF);
    }

    public void setVariant(int i) {
        if (i == 0x05) {
            icvEnc = false;
        }
    }

    public CommandAPDU wrap(CommandAPDU command) throws GPException {
        try {
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
                if (icv == null) {
                    icv = new byte[8];
                } else if (icvEnc) {
                    Cipher c = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
                    c.init(Cipher.ENCRYPT_MODE, GPCrypto.des3key(sessionKeys.get(MAC)));
                    icv = c.doFinal(icv);
                }

                if (preAPDU) {
                    newCLA = setBits((byte) newCLA, (byte) 0x04);
                    newLc = newLc + 8;
                }
                t.write(newCLA);
                t.write(origINS);
                t.write(origP1);
                t.write(origP2);
                t.write(newLc);
                t.write(origData);

                icv = GPCrypto.mac_3des(sessionKeys.get(MAC), t.toByteArray(), icv);

                if (postAPDU) {
                    newCLA = setBits((byte) newCLA, (byte) 0x04);
                    newLc = newLc + 8;
                }
                t.reset();
                newData = origData;
            }

            if (enc && (origLc > 0)) {
                // Prepend length to padding

                t.write(origLc);
                t.write(origData);
                if ((t.size() % 8) != 0) {
                    byte[] x = GPCrypto.pad80(t.toByteArray(), 8);
                    t.reset();
                    t.write(x);
                }

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
        return response;
    }
}
