package pro.javacard.pace;

import apdu4j.core.*;
import com.payneteasy.tlv.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

// Secure channel around CardChannel.transmit() apdu4j.CommandAPDU/ResponseAPDU pairs
// TR 03110-3: F.Secure Messaging (Normative)
public final class AESSecureChannel implements BIBO {
    private static final Logger log = LoggerFactory.getLogger(AESSecureChannel.class);

    private final byte[] ssc;
    private final byte[] mac_key;
    private final byte[] enc_key;
    final BIBO channel;

    public AESSecureChannel(byte[] enc, byte[] mac, BIBO channel) {
        enc_key = enc.clone();
        mac_key = mac.clone();
        this.ssc = new byte[16];
        this.channel = channel;
    }

    public CommandAPDU wrap(CommandAPDU apdu) throws GeneralSecurityException, IOException {
        log.debug("CommandAPDU  : {}", HexUtils.bin2hex(apdu.getBytes()));
        // Increment SSC
        buffer_increment(ssc);
        log.trace("Command SSC  : {}", HexUtils.bin2hex(ssc));

        // IV is encryption of the SSC
        byte[] iv = encrypt(enc_key, new byte[16], ssc);
        log.trace("IV           : {}", HexUtils.bin2hex(iv));

        int cla = apdu.getCLA() | 0x0C;
        int ins = apdu.getINS();
        int p1 = apdu.getP1();
        int p2 = apdu.getP2();

        // Construct mac input
        ByteArrayOutputStream macinput = new ByteArrayOutputStream();
        // Prepend SSC
        macinput.write(ssc);

        // Add APDU header
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(cla);
        header.write(ins);
        header.write(p1);
        header.write(p2);

        // Add header, padded to block size
        macinput.write(pad80(header.toByteArray(), 16));

        final byte[] newdata;

        // Encrypt payload
        if (apdu.getData().length > 0) {
            byte[] plaintext = pad80(apdu.getData(), 16);
            log.trace("ENC payload  : {}", HexUtils.bin2hex(plaintext));
            byte[] cgram = encrypt(enc_key, iv, plaintext);

            // TLV header. +1 for padding indicator (0x01)
            newdata = concatenate(new byte[]{(byte) 0x87, (byte) (cgram.length + 1), 0x01}, cgram);
            log.trace("New payload  : {}", HexUtils.bin2hex(newdata));

            // Le FIXME: only short size currently ?
            macinput.write(pad80(concatenate(newdata, new byte[]{(byte) 0x97, 0x01, (byte) apdu.getNe()}), 16));
        } else {
            newdata = new byte[0];
            // Add Le to mac
            macinput.write(pad80(new byte[]{(byte) 0x97, 0x01, (byte) apdu.getNe()}, 16));
        }

        log.trace("MAC input    : {}", HexUtils.bin2hex(macinput.toByteArray()));
        // Calculate mac
        byte[] mac = PACE.aes_mac8(mac_key, macinput.toByteArray());
        log.trace("Calculated MAC: {}", HexUtils.bin2hex(mac));

        // Construct new payload
        ByteArrayOutputStream payload = new ByteArrayOutputStream();

        // encrypted data with 0x87 header
        if (apdu.getData().length > 0)
            payload.write(newdata);

        //if (apdu.getNe() == 0x00)
        payload.write(new byte[]{(byte) 0x97, 0x01, (byte) apdu.getNe()});

        // append mac
        payload.write(0x8e);
        payload.write(mac.length);
        payload.write(mac);

        return new CommandAPDU(cla, ins, p1, p2, payload.toByteArray(), 256);
    }

    public ResponseAPDU unwrap(ResponseAPDU apdu) throws SecureChannelException, IOException, GeneralSecurityException {
        if (apdu.getSW() == 0x6987)
            throw new SecureChannelException("Expected Secure Messaging data objects are missing");
        if (apdu.getSW() == 0x6988)
            throw new SecureChannelException("Secure Messaging data objects are incorrect");

        buffer_increment(ssc);
        log.trace("Response SSC  : {}", HexUtils.bin2hex(ssc));
        ByteArrayOutputStream fresh = new ByteArrayOutputStream();
        ByteArrayOutputStream macinput = new ByteArrayOutputStream();
        // Prepend SSC
        macinput.write(ssc);

        byte[] cardmac = null;

        BerTlvParser parser = new BerTlvParser();
        BerTlvs tlvs = parser.parse(apdu.getData());

        BerTlv payloadtag = tlvs.find(new BerTag(0x87));
        if (payloadtag != null) {
            byte[] iv = encrypt(enc_key, new byte[16], ssc);
            log.trace("IV           : {}", HexUtils.bin2hex(iv));

            byte[] payload = payloadtag.getBytesValue();
            byte[] cgram = Arrays.copyOfRange(payload, 1, payload.length);
            log.trace("cgram        : {}", HexUtils.bin2hex(cgram));

            byte[] plaintext = decrypt(enc_key, iv, cgram);
            log.trace("plaintext    : {}", HexUtils.bin2hex(plaintext));

            fresh.write(unpad80(plaintext));
            macinput.write(new BerTlvBuilder().addBytes(new BerTag(0x87), payload).buildArray());
        }

        BerTlv swtag = tlvs.find(new BerTag(0x99));
        if (swtag != null) {
            macinput.write(new BerTlvBuilder().addBytes(new BerTag(0x99), swtag.getBytesValue()).buildArray());
            fresh.write(swtag.getBytesValue());
        }
        BerTlv mactag = tlvs.find(new BerTag(0x8e));
        if (mactag != null) {
            cardmac = mactag.getBytesValue();
        }

        // Calculate mac
        byte[] mac = PACE.aes_mac8(mac_key, pad80(macinput.toByteArray(), 16));
        log.trace("Our mac       : {}", HexUtils.bin2hex(mac));

        if (!Arrays.equals(cardmac, mac))
            throw new SecureChannelException("Secure channel response MAC failed");
        byte[] responseapdu = fresh.toByteArray();
        log.debug("ResponseAPDU : {}", HexUtils.bin2hex(responseapdu));
        return new ResponseAPDU(responseapdu);
    }

    public static byte[] pad80(byte[] text, int blocksize) {
        int total = (text.length / blocksize + 1) * blocksize;
        byte[] result = Arrays.copyOfRange(text, 0, total);
        result[text.length] = (byte) 0x80;
        return result;
    }


    public static byte[] unpad80(byte[] buffer) throws BadPaddingException {
        if (buffer.length < 1)
            throw new BadPaddingException("Invalid ISO 7816-4 padding");
        int offset = buffer.length - 1;
        while (offset > 0 && buffer[offset] == 0) {
            offset--;
        }
        if (buffer[offset] != (byte) 0x80) {
            throw new BadPaddingException("Invalid ISO 7816-4 padding");
        }
        return Arrays.copyOf(buffer, offset);
    }

    private static void buffer_increment(byte[] buffer, int offset, int len) {
        if (len < 1)
            return;
        for (int i = offset + len - 1; i >= offset; i--) {
            if (buffer[i] != (byte) 0xFF) {
                buffer[i]++;
                break;
            } else
                buffer[i] = (byte) 0x00;
        }
    }

    public static void buffer_increment(byte[] buffer) {
        buffer_increment(buffer, 0, buffer.length);
    }


    @Override
    public byte[] transceive(byte[] bytes) throws BIBOException {
        try {
            byte[] payload = wrap(new CommandAPDU(bytes)).getBytes();
            ResponseAPDU r = new ResponseAPDU(channel.transceive(payload));
            return unwrap(r).getBytes();
        } catch (GeneralSecurityException | IOException e) {
            throw new BIBOException("Could not wrap/unwrap: " + e.getMessage(), e);
        }
    }

    @Override
    public void close() {
        Arrays.fill(mac_key, (byte) 0x00);
        Arrays.fill(enc_key, (byte) 0x00);
    }

    public int getMaxTransceiveLength() {
        int chunksize = 256 - 18 - 16; // FIXME WTF ?
        return chunksize;
    }

    public static byte[] concatenate(byte[]... args) {
        int length = 0, pos = 0;
        for (byte[] arg : args) {
            length += arg.length;
        }
        byte[] result = new byte[length];
        for (byte[] arg : args) {
            System.arraycopy(arg, 0, result, pos, arg.length);
            pos += arg.length;
        }
        return result;
    }

    static byte[] encrypt(byte[] key, byte[] iv, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    static byte[] decrypt(byte[] key, byte[] iv, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }
}
