// SPDX-FileCopyrightText: 2020 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.tlv.TLV;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.SecretKey;

// NOTE: Thanks goes to Gregor Johannson for initial implementation
public abstract class DMTokenizer {
    private static final Logger log = LoggerFactory.getLogger(DMTokenizer.class);

    protected DMTokenizer() {}

    protected abstract byte[] getToken(CommandAPDU apdu);

    protected abstract boolean canTokenize(CommandAPDU apdu);

    public CommandAPDU tokenize(final CommandAPDU apdu) {
        final var data = new ByteArrayOutputStream();
        data.writeBytes(apdu.getData());
        if (!canTokenize(apdu)) {
            throw new IllegalArgumentException("No DM token for APDU: " + apdu);
        }
        final var token = getToken(apdu);

        if (token.length > 0) {
            // DELETE carries the token in a 9E TLV; other commands append it as a bare length-value
            if (apdu.getINS() == 0xE4) {
                data.writeBytes(TLV.of(0x9E, token).encode());
            } else {
                data.writeBytes(GPUtils.encodeLength(token.length));
                data.writeBytes(token);
            }
        } else {
            if (apdu.getINS() != 0xE4) {
                data.write(0); // No token in LV chain and no tag in TLV case
            }
        }
        return new CommandAPDU(apdu.getCLA(), apdu.getINS(), apdu.getP1(), apdu.getP2(), data.toByteArray()); // FIXME: Le handling
    }

    protected byte[] dtbs(final CommandAPDU apdu) {
        final var bo = new ByteArrayOutputStream();
        bo.write(apdu.getP1());
        bo.write(apdu.getP2());
        bo.writeBytes(GPUtils.encodeLcLength(apdu.getData().length, apdu.getNe()));
        bo.writeBytes(apdu.getData());
        return bo.toByteArray();
    }

    public static DMTokenizer forPrivateKey(final RSAPrivateKey pkey) {
        return new RSATokenizer(pkey);
    }

    public static DMTokenizer forAESKey(final SecretKey key) {
        return new AESTokenizer(key);
    }

    public static DMTokenizer forToken(final byte[] token) {
        return new StaticTokenizer(token);
    }

    public static DMTokenizer none() {
        return new NULLTokenizer();
    }

    // RSA key, any token
    static class RSATokenizer extends DMTokenizer {

        private final RSAPrivateKey privateKey;

        RSATokenizer(final RSAPrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        @Override
        protected boolean canTokenize(final CommandAPDU apdu) {
            return true;
        }

        @Override
        protected byte[] getToken(final CommandAPDU apdu) {
            final var dtbs = dtbs(apdu);

            try {
                final byte[] token = GPCrypto.rsa_sign(privateKey, dtbs);
                log.trace("DM token: {}", HexUtils.bin2hex(token));
                return token;
            } catch (GeneralSecurityException e) {
                throw new GPException("Can not calculate DM token: " + e.getMessage(), e);
            }
        }
    }

    // AES CMAC token - GP 2.3.1 section B.2.2 and C.4
    static class AESTokenizer extends DMTokenizer {

        private final SecretKey key;

        AESTokenizer(final SecretKey key) {
            this.key = key;
        }

        @Override
        protected boolean canTokenize(final CommandAPDU apdu) {
            return true;
        }

        @Override
        protected byte[] getToken(final CommandAPDU apdu) {
            final var dtbs = dtbs(apdu);
            try {
                final byte[] token = GPCrypto.aes_cmac(key, dtbs, 128);
                log.trace("DM token: {}", HexUtils.bin2hex(token));
                return token;
            } catch (GeneralSecurityException e) {
                throw new GPException("Can not calculate DM token: " + e.getMessage(), e);
            }
        }
    }

    // No key, zero token
    static class NULLTokenizer extends DMTokenizer {

        @Override
        protected byte[] getToken(final CommandAPDU apdu) {
            return new byte[0];
        }

        @Override
        protected boolean canTokenize(final CommandAPDU apdu) {
            return true;
        }
    }

    // Static token
    static class StaticTokenizer extends DMTokenizer {

        // TODO: different existing tokens for different operations
        private final byte[] token;
        private boolean used = false;

        StaticTokenizer(final byte[] token) {
            this.token = token;
        }

        @Override
        protected byte[] getToken(final CommandAPDU apdu) {
            used = true;
            return token;
        }

        @Override
        protected boolean canTokenize(final CommandAPDU apdu) {
            return !used;
        }
    }
}
