/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2024-present Martin Paljak, martin@martinpaljak.net
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

import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.capfile.AID;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;

public abstract class ReceiptVerifier {

    protected ReceiptVerifier() {}
    private static final Logger log = LoggerFactory.getLogger(ReceiptVerifier.class);

    static byte[] get_receipt(byte[] response) {
        return Arrays.copyOfRange(response, 2, 2 + response[1]);
    }

    static byte[] get_confirmation_data(byte[] response) {
        return Arrays.copyOfRange(response, 2 + response[1], response[0] + 1);
    }

    abstract boolean check(ResponseAPDU response, byte[] context);
    boolean log_only = false;

    static public class AESReceiptVerifier extends ReceiptVerifier {
        private final byte[] aes_key;

        public AESReceiptVerifier(byte[] aesKey) {
            aes_key = aesKey.clone();
        }

        public AESReceiptVerifier(byte[] aesKey, boolean log_only) {
            aes_key = aesKey.clone();
            this.log_only = log_only;
        }

        // XXX: the use of "log only" arguments, boolean function and exceptions is not nice. Refactor
        @Override
        boolean check(ResponseAPDU response, byte[] context) throws ReceiptVerificationException {
            // Context is the concatenation of command parameters sent to the card before receiving the receipt.
            byte[] data = response.getData();
            if (data[0] == 0x00) {
                log.debug("No receipt");
                return true;
            }
            try {
                GPUtils.trace_lv(Arrays.copyOfRange(data, 1, data[0]), log);
            } catch (Exception e) {
                log.error("Invalid LV in response: {}", HexUtils.bin2hex(data));
            }
            byte[] card = get_receipt(data);
            byte[] confdata = get_confirmation_data(data);

            byte[] my = GPCrypto.aes_cmac(aes_key, GPUtils.concatenate(confdata, context), 128);
            boolean verified = Arrays.equals(my, card);
            if (!verified) {
                log.error("Receipt verification failed");
                if (!log_only) {
                    throw new ReceiptVerificationException("Receipt verification failed");
                }
            } else {
                log.info("Receipt verified successfully");
            }
            return verified;
        }
    }

    // Verifier that never complains.
    static public class NullVerifier extends ReceiptVerifier {

        public NullVerifier() {
        }

        @Override
        boolean check(ResponseAPDU response, byte[] context) {
            return true;
        }
    }

    // Context data generators for different operatings and receipt types.
    public static byte[] load(AID pkg, AID sd) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(pkg.getLength());
            baos.write(pkg.getBytes());
            baos.write(sd.getLength());
            baos.write(sd.getBytes());
            return baos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] install_make_selectable(AID pkg, AID instance) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(pkg.getLength());
            baos.write(pkg.getBytes());
            baos.write(instance.getLength());
            baos.write(instance.getBytes());
            return baos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }


    public static byte[] extradite(AID from, AID what, AID to) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(from.getLength());
            baos.write(from.getBytes());
            baos.write(what.getLength());
            baos.write(what.getBytes());
            baos.write(to.getLength());
            baos.write(to.getBytes());
            return baos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] delete(AID what) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(what.getLength());
            baos.write(what.getBytes());
            return baos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static class ReceiptVerificationException extends RuntimeException {
        private static final long serialVersionUID = -453299698747234135L;
        public ReceiptVerificationException(String message) {
            super(message);
        }
    }
    // TODO: registry update
    // TODO: Combined Load, Install and Make Selectable
}
