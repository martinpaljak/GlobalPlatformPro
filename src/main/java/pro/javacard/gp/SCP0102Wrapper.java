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

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.EnumSet;

class SCP0102Wrapper extends SecureChannelWrapper {

    private final ByteArrayOutputStream rMac = new ByteArrayOutputStream();
    private byte[] icv = null;
    private byte[] ricv = null;
    private int scp = 0;
    private boolean icvEnc = false;

    private boolean preAPDU = false;
    private boolean postAPDU = false;


    SCP0102Wrapper(GPSessionKeyProvider sessionKeys, int scp, EnumSet<GlobalPlatform.APDUMode> securityLevel, byte[] icv, byte[] ricv, int bs) {
        this.blockSize = bs;
        this.sessionKeys = sessionKeys;
        this.icv = icv;
        this.ricv = ricv;
        setSCPVersion(scp);
        setSecurityLevel(securityLevel);
    }

    private static byte clearBits(byte b, byte mask) {
        return (byte) ((b & ~mask) & 0xFF);
    }

    private static byte setBits(byte b, byte mask) {
        return (byte) ((b | mask) & 0xFF);
    }

    public void setSCPVersion(int scp) {
        // Major version of wrapper
        this.scp = 2;
        if (scp < GlobalPlatform.SCP_02_04) {
            this.scp = 1;
        }

        // modes
        if ((scp == GlobalPlatform.SCP_01_15) || (scp == GlobalPlatform.SCP_02_14) || (scp == GlobalPlatform.SCP_02_15) || (scp == GlobalPlatform.SCP_02_1A) || (scp == GlobalPlatform.SCP_02_1B)) {
            icvEnc = true;
        } else {
            icvEnc = false;
        }
        if ((scp == GlobalPlatform.SCP_01_05) || (scp == GlobalPlatform.SCP_01_15) || (scp == GlobalPlatform.SCP_02_04) || (scp == GlobalPlatform.SCP_02_05) || (scp == GlobalPlatform.SCP_02_14) || (scp == GlobalPlatform.SCP_02_15)) {
            preAPDU = true;
        } else {
            preAPDU = false;
        }
        if ((scp == GlobalPlatform.SCP_02_0A) || (scp == GlobalPlatform.SCP_02_0B) || (scp == GlobalPlatform.SCP_02_1A) || (scp == GlobalPlatform.SCP_02_1B)) {
            postAPDU = true;
        } else {
            postAPDU = false;
        }
    }

    public byte[] getIV() {
        return icv;
    }

    public void setRMACIV(byte[] iv) {
        ricv = iv;
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
                if (icv == null) {
                    icv = new byte[8];
                } else if (icvEnc) {
                    Cipher c = null;
                    if (scp == 1) {
                        c = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
                        c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC).getKeyAs(GPKey.Type.DES3));
                    } else {
                        c = Cipher.getInstance(GPCrypto.DES_ECB_CIPHER);
                        c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC).getKeyAs(GPKey.Type.DES));
                    }
                    // encrypts the future ICV ?
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

                if (scp == 1) {
                    icv = GPCrypto.mac_3des(sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC), t.toByteArray(), icv);
                } else if (scp == 2) {
                    icv = GPCrypto.mac_des_3des(sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC), t.toByteArray(), icv);
                }

                if (postAPDU) {
                    newCLA = setBits((byte) newCLA, (byte) 0x04);
                    newLc = newLc + 8;
                }
                t.reset();
                newData = origData;
            }

            if (enc && (origLc > 0)) {
                if (scp == 1) {
                    t.write(origLc);
                    t.write(origData);
                    if ((t.size() % 8) != 0) {
                        byte[] x = GPCrypto.pad80(t.toByteArray(), 8);
                        t.reset();
                        t.write(x);
                    }
                } else {
                    t.write(GPCrypto.pad80(origData, 8));
                }
                newLc += t.size() - origData.length;

                Cipher c = Cipher.getInstance(GPCrypto.DES3_CBC_CIPHER);
                c.init(Cipher.ENCRYPT_MODE, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.ENC).getKeyAs(GPKey.Type.DES3), GPCrypto.iv_null_8);
                newData = c.doFinal(t.toByteArray());
                t.reset();
            }
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
                throw new RuntimeException("Wrong response length (too short).");
            }
            int respLen = response.getData().length - 8;
            rMac.write(respLen);
            rMac.write(response.getData(), 0, respLen);
            rMac.write(response.getSW1());
            rMac.write(response.getSW2());

            ricv = GPCrypto.mac_des_3des(sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.RMAC), GPCrypto.pad80(rMac.toByteArray(), 8), ricv);

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
