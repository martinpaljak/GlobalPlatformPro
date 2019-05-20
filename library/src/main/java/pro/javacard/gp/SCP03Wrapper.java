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

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.EnumSet;

import static pro.javacard.gp.GPCardKeys.KeyPurpose.ENC;
import static pro.javacard.gp.GPCardKeys.KeyPurpose.RMAC;

class SCP03Wrapper extends SecureChannelWrapper {
    // Both are block size length
    byte[] chaining_value = new byte[16];
    byte[] encryption_counter = new byte[16];

    SCP03Wrapper(GPSessionKeys sessionKeys, EnumSet<GPSession.APDUMode> securityLevel, int bs) {
        super(sessionKeys, securityLevel, bs);
    }

    @Override
    protected CommandAPDU wrap(CommandAPDU command) throws GPException {
        byte[] cmd_mac = null;

        try {
            int cla = command.getCLA();
            int lc = command.getNc();
            byte[] data = command.getData();

            // Encrypt if needed
            if (enc) {
                cla = 0x84;
                // Counter shall always be incremented
                GPCrypto.buffer_increment(encryption_counter);
                if (command.getData().length > 0) {
                    byte[] d = GPCrypto.pad80(command.getData(), 16);
                    // Encrypt with S-ENC, after increasing the counter
                    Cipher c = Cipher.getInstance(GPCrypto.AES_CBC_CIPHER);
                    c.init(Cipher.ENCRYPT_MODE, GPCrypto.aeskey(sessionKeys.get(ENC)), GPCrypto.iv_null_16);
                    byte[] iv = c.doFinal(encryption_counter);
                    // Now encrypt the data with S-ENC.
                    c.init(Cipher.ENCRYPT_MODE, GPCrypto.aeskey(sessionKeys.get(ENC)), new IvParameterSpec(iv));
                    data = c.doFinal(d);
                    lc = data.length;
                }
            }
            // Calculate C-MAC
            if (mac) {
                cla = 0x84;
                lc = lc + 8;

                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                bo.write(chaining_value);
                bo.write(cla);
                bo.write(command.getINS());
                bo.write(command.getP1());
                bo.write(command.getP2());
                bo.write(GPUtils.encodeLcLength(lc));
                bo.write(data);
                byte[] cmac_input = bo.toByteArray();
                byte[] cmac = GPCrypto.scp03_mac(sessionKeys.get(GPCardKeys.KeyPurpose.MAC), cmac_input, 128);
                // Set new chaining value
                System.arraycopy(cmac, 0, chaining_value, 0, chaining_value.length);
                // 8 bytes for actual mac
                cmd_mac = Arrays.copyOf(cmac, 8);
            }
            // Constructing new a new command APDU ensures that the coding of LC and NE is correct; especially for Extend Length APDUs
            CommandAPDU newAPDU = null;

            ByteArrayOutputStream newData = new ByteArrayOutputStream();
            newData.write(data);
            if (mac) {
                newData.write(cmd_mac);
            }
            if (command.getNe() > 0) {
                newAPDU = new CommandAPDU(cla, command.getINS(), command.getP1(), command.getP2(), newData.toByteArray(), command.getNe());
            } else {
                newAPDU = new CommandAPDU(cla, command.getINS(), command.getP1(), command.getP2(), newData.toByteArray());
            }
            return newAPDU;

        } catch (IOException e) {
            throw new RuntimeException("APDU wrapping failed", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("APDU wrapping failed", e);
        } catch (GeneralSecurityException e) {
            throw new GPException("APDU wrapping failed", e);
        }
    }

    @Override
    protected ResponseAPDU unwrap(ResponseAPDU response) throws GPException {
        try {
            if (rmac) {
                if (response.getData().length < 8) {
                    throw new RuntimeException("Wrong response length (too short)."); // FIXME: bad exception
                }
                int respLen = response.getData().length - 8;

                byte[] actualMac = new byte[8];
                System.arraycopy(response.getData(), respLen, actualMac, 0, 8);

                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                bo.write(chaining_value);
                bo.write(response.getData(), 0, respLen);
                bo.write(response.getSW1());
                bo.write(response.getSW2());

                byte[] cmac_input = bo.toByteArray();

                byte[] cmac = GPCrypto.scp03_mac(sessionKeys.get(RMAC), cmac_input, 128);

                // 8 bytes for actual mac
                byte[] resp_mac = Arrays.copyOf(cmac, 8);

                if (!Arrays.equals(resp_mac, actualMac)) {
                    throw new GPException("RMAC invalid: " + HexUtils.bin2hex(actualMac) + " vs " + HexUtils.bin2hex(resp_mac));
                }

                ByteArrayOutputStream o = new ByteArrayOutputStream();
                o.write(response.getBytes(), 0, respLen);
                o.write(response.getSW1());
                o.write(response.getSW2());
                response = new ResponseAPDU(o.toByteArray());
            }
            if (renc && response.getData().length > 0) {
                // Encrypt with S-ENC, after changing the first byte of the counter
                byte[] response_encryption_counter = Arrays.copyOf(encryption_counter, encryption_counter.length);
                response_encryption_counter[0] = (byte) 0x80;
                Cipher c = Cipher.getInstance(GPCrypto.AES_CBC_CIPHER);
                c.init(Cipher.ENCRYPT_MODE, GPCrypto.aeskey(sessionKeys.get(ENC)), GPCrypto.iv_null_16);
                byte[] iv = c.doFinal(response_encryption_counter);
                // Now decrypt the data with S-ENC, with the new IV
                c.init(Cipher.DECRYPT_MODE, GPCrypto.aeskey(sessionKeys.get(ENC)), new IvParameterSpec(iv));
                byte[] data = c.doFinal(response.getData());
                ByteArrayOutputStream o = new ByteArrayOutputStream();
                o.write(GPCrypto.unpad80(data));
                o.write(response.getSW1());
                o.write(response.getSW2());
                response = new ResponseAPDU(o.toByteArray());
            }
            return response;
        } catch (IOException e) {
            throw new RuntimeException("APDU unwrapping failed", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("APDU unwrapping failed", e);
        } catch (GeneralSecurityException e) {
            throw new GPException("APDU unwrapping failed", e);
        }
    }
}
