// SPDX-FileCopyrightText: 2024 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.pace;

import apdu4j.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static pro.javacard.tlv.TLV.ba;

// Secure channel around CardChannel.transmit() apdu4j.CommandAPDU/ResponseAPDU pairs
// TR 03110-3: F.Secure Messaging (Normative)
public final class AESSecureChannel implements BIBO {
    private static final Logger log = LoggerFactory.getLogger(AESSecureChannel.class);

    private final byte[] ssc;
    private final byte[] mac_key;
    private final byte[] enc_key;
    final BIBO channel;

    public AESSecureChannel(final byte[] enc, final byte[] mac, final BIBO channel) {
        enc_key = enc.clone();
        mac_key = mac.clone();
        this.ssc = new byte[16];
        this.channel = channel;
    }

    public CommandAPDU wrap(final CommandAPDU apdu) throws GeneralSecurityException {
        log.debug("CommandAPDU  : {}", HexUtils.bin2hex(apdu.getBytes()));
        // Increment SSC
        buffer_increment(ssc);
        log.trace("Command SSC  : {}", HexUtils.bin2hex(ssc));

        // IV is encryption of the SSC
        final byte[] iv = encrypt(enc_key, new byte[16], ssc);
        log.trace("IV           : {}", HexUtils.bin2hex(iv));

        final var cla = apdu.getCLA() | 0x0C;
        final var ins = apdu.getINS();
        final var p1 = apdu.getP1();
        final var p2 = apdu.getP2();

        // Construct mac input
        final var macinput = new ByteArrayOutputStream();
        // Prepend SSC
        macinput.writeBytes(ssc);

        // Add APDU header
        final var header = new ByteArrayOutputStream();
        header.write(cla);
        header.write(ins);
        header.write(p1);
        header.write(p2);

        // Add header, padded to block size
        macinput.writeBytes(pad80(header.toByteArray(), 16));

        final byte[] newdata;

        // Le (97) data object, appended to both the MAC input and the wrapped payload.
        // Ne can be 256 (one short-form byte), which wraps to 0x00 - hence the explicit mask.
        final var leDO = TLV.of(0x97, ba(apdu.getNe() & 0xFF)).encode();

        // Encrypt payload
        if (apdu.getData().length > 0) {
            final byte[] plaintext = pad80(apdu.getData(), 16);
            log.trace("ENC payload  : {}", HexUtils.bin2hex(plaintext));
            final byte[] cgram = encrypt(enc_key, iv, plaintext);

            // 87 cryptogram data object; value is the padding indicator (0x01) followed by the cryptogram
            newdata = TLV.of(0x87, concatenate(ba(0x01), cgram)).encode();
            log.trace("New payload  : {}", HexUtils.bin2hex(newdata));

            // Le FIXME: only short size currently ?
            macinput.writeBytes(pad80(concatenate(newdata, leDO), 16));
        } else {
            newdata = new byte[0];
            // Add Le to mac
            macinput.writeBytes(pad80(leDO, 16));
        }

        log.trace("MAC input    : {}", HexUtils.bin2hex(macinput.toByteArray()));
        // Calculate mac
        final byte[] mac = PACE.aes_mac8(mac_key, macinput.toByteArray());
        log.trace("Calculated MAC: {}", HexUtils.bin2hex(mac));

        // Construct new payload
        final var payload = new ByteArrayOutputStream();

        // encrypted data with 0x87 header
        if (apdu.getData().length > 0) {
            payload.writeBytes(newdata);
        }

        //if (apdu.getNe() == 0x00)
        payload.writeBytes(leDO);

        // append mac in the 8E cryptographic checksum data object
        payload.writeBytes(TLV.of(0x8E, mac).encode());

        return new CommandAPDU(cla, ins, p1, p2, payload.toByteArray(), 256);
    }

    public ResponseAPDU unwrap(final ResponseAPDU apdu) throws SecureChannelException, GeneralSecurityException {
        if (apdu.getSW() == 0x6987) {
            throw new SecureChannelException("Expected Secure Messaging data objects are missing");
        }
        if (apdu.getSW() == 0x6988) {
            throw new SecureChannelException("Secure Messaging data objects are incorrect");
        }

        buffer_increment(ssc);
        log.trace("Response SSC  : {}", HexUtils.bin2hex(ssc));
        final var fresh = new ByteArrayOutputStream();
        final var macinput = new ByteArrayOutputStream();
        // Prepend SSC
        macinput.writeBytes(ssc);

        final var tlvs = TLV.parse(apdu.getData());

        // Encrypted response data (optional); crypto below throws checked exceptions, so no lambda
        final var payloadtag = tlvs.find(0x87);
        if (payloadtag.isPresent()) {
            final byte[] iv = encrypt(enc_key, new byte[16], ssc);
            log.trace("IV           : {}", HexUtils.bin2hex(iv));

            final var payload = payloadtag.get().value();
            final byte[] cgram = Arrays.copyOfRange(payload, 1, payload.length);
            log.trace("cgram        : {}", HexUtils.bin2hex(cgram));

            final byte[] plaintext = decrypt(enc_key, iv, cgram);
            log.trace("plaintext    : {}", HexUtils.bin2hex(plaintext));

            fresh.writeBytes(unpad80(plaintext));
            macinput.writeBytes(TLV.of(Tag.ber(0x87), payload).encode());
        }

        // The processing status (tag 99) is mandatory
        final var sw = tlvs.find(0x99).map(TLV::value)
                .orElseThrow(() -> new SecureChannelException("Response status (tag 99) missing"));
        macinput.writeBytes(TLV.of(Tag.ber(0x99), sw).encode());
        fresh.writeBytes(sw);

        // The response MAC (tag 8E) is mandatory
        final var cardmac = tlvs.find(0x8e).map(TLV::value)
                .orElseThrow(() -> new SecureChannelException("Response MAC (tag 8E) missing"));

        // Calculate mac
        final byte[] mac = PACE.aes_mac8(mac_key, pad80(macinput.toByteArray(), 16));
        log.trace("Our mac       : {}", HexUtils.bin2hex(mac));

        if (!Arrays.equals(cardmac, mac)) {
            throw new SecureChannelException("Secure channel response MAC failed");
        }
        final var responseapdu = fresh.toByteArray();
        log.debug("ResponseAPDU : {}", HexUtils.bin2hex(responseapdu));
        return new ResponseAPDU(responseapdu);
    }

    public static byte[] pad80(final byte[] text, final int blocksize) {
        final var total = (text.length / blocksize + 1) * blocksize;
        final byte[] result = Arrays.copyOfRange(text, 0, total);
        result[text.length] = (byte) 0x80;
        return result;
    }

    public static byte[] unpad80(final byte[] buffer) throws BadPaddingException {
        if (buffer.length < 1) {
            throw new BadPaddingException("Invalid ISO 7816-4 padding");
        }
        var offset = buffer.length - 1;
        while (offset > 0 && buffer[offset] == 0) {
            offset--;
        }
        if (buffer[offset] != (byte) 0x80) {
            throw new BadPaddingException("Invalid ISO 7816-4 padding");
        }
        return Arrays.copyOf(buffer, offset);
    }

    private static void buffer_increment(byte[] buffer, int offset, int len) {
        if (len < 1) {
            return;
        }
        for (var i = offset + len - 1; i >= offset; i--) {
            if (buffer[i] != (byte) 0xFF) {
                buffer[i]++;
                break;
            } else {
                buffer[i] = (byte) 0x00;
            }
        }
    }

    public static void buffer_increment(final byte[] buffer) {
        buffer_increment(buffer, 0, buffer.length);
    }

    @Override
    public byte[] transceive(final byte[] bytes) throws BIBOException {
        try {
            final var payload = wrap(new CommandAPDU(bytes)).getBytes();
            final var r = new ResponseAPDU(channel.transceive(payload));
            return unwrap(r).getBytes();
        } catch (GeneralSecurityException e) {
            throw new BIBOException("Could not wrap/unwrap: " + e.getMessage(), e);
        }
    }

    @Override
    public void close() {
        Arrays.fill(mac_key, (byte) 0x00);
        Arrays.fill(enc_key, (byte) 0x00);
    }

    public int getMaxTransceiveLength() {
        final var chunksize = 256 - 18 - 16; // FIXME WTF ?
        return chunksize;
    }

    public static byte[] concatenate(final byte[]... args) {
        var length = 0;
        var pos = 0;
        for (byte[] arg : args) {
            length += arg.length;
        }
        final byte[] result = new byte[length];
        for (byte[] arg : args) {
            System.arraycopy(arg, 0, result, pos, arg.length);
            pos += arg.length;
        }
        return result;
    }

    static byte[] encrypt(final byte[] key, final byte[] iv, final byte[] data) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    static byte[] decrypt(final byte[] key, final byte[] iv, final byte[] data) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }
}
