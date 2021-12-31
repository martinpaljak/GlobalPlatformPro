/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2020-present Martin Paljak, martin@martinpaljak.net
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

import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;

// NOTE: Thanks goes to Gregor Johannson for initial implementation
public abstract class DMTokenizer {
    private static final Logger logger = LoggerFactory.getLogger(DMTokenizer.class);

    abstract protected byte[] getToken(CommandAPDU apdu);

    abstract protected boolean canTokenize(CommandAPDU apdu);

    public CommandAPDU tokenize(CommandAPDU apdu) {
        try {
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            data.write(apdu.getData());
            if (!canTokenize(apdu))
                throw new IllegalArgumentException("No DM token for APDU: " + apdu);

            byte[] token = getToken(apdu);

            if (token.length > 0) {
                // Handle DELETE and prefix with tag
                if (apdu.getINS() == 0xE4)
                    data.write(0x9E);
                data.write(GPUtils.encodeLength(token.length));
                data.write(token);
            } else {
                if (apdu.getINS() != 0xE4)
                    data.write(0); // No token in LV chain and no tag in TLV case
            }
            return new CommandAPDU(apdu.getCLA(), apdu.getINS(), apdu.getP1(), apdu.getP2(), data.toByteArray()); // FIXME: Le handling
        } catch (IOException e) {
            throw new GPException("Could not tokenize APDU: " + e.getMessage(), e);
        }
    }

    protected byte[] dtbs(CommandAPDU apdu) {
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            bo.write(apdu.getP1());
            bo.write(apdu.getP2());
            bo.write(apdu.getData().length); // FIXME: length handling for > 255 bytes
            bo.write(apdu.getData());
            return bo.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Memory error", e);
        }
    }

    public static DMTokenizer forPrivateKey(RSAPrivateKey pkey) {
        return new RSATokenizer(pkey);
    }

    public static DMTokenizer forToken(byte[] token) {
        return new StaticTokenizer(token);
    }

    public static DMTokenizer none() {
        return new NULLTokenizer();
    }

    // RSA key, any token
    static class RSATokenizer extends DMTokenizer {

        private final RSAPrivateKey privateKey;

        RSATokenizer(RSAPrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        @Override
        protected boolean canTokenize(CommandAPDU apdu) {
            return true;
        }

        @Override
        protected byte[] getToken(CommandAPDU apdu) {
            try {
                Signature signer = Signature.getInstance("SHA1withRSA");
                signer.initSign(privateKey);
                signer.update(dtbs(apdu));
                byte[] signature = signer.sign();
                logger.debug("Generated DM token: {}", HexUtils.bin2hex(signature));
                return signature;
            } catch (GeneralSecurityException e) {
                throw new GPException("Can not calculate DM token: " + e.getMessage(), e);
            }
        }
    }

    // No key, zero token
    static class NULLTokenizer extends DMTokenizer {

        @Override
        protected byte[] getToken(CommandAPDU apdu) {
            return new byte[0];
        }

        @Override
        protected boolean canTokenize(CommandAPDU apdu) {
            return true;
        }
    }

    // Static token
    static class StaticTokenizer extends DMTokenizer {

        // TODO: different existing tokens for different operations
        private final byte[] token;

        StaticTokenizer(byte[] token) {
            this.token = token;
        }

        @Override
        protected byte[] getToken(CommandAPDU apdu) {
            return token;
        }

        @Override
        protected boolean canTokenize(CommandAPDU apdu) {
            return true;
        }
    }
}
