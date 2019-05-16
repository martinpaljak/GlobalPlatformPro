package pro.javacard.gp;

import apdu4j.CommandAPDU;
import apdu4j.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import static pro.javacard.gp.GPSession.INS_DELETE;

public class DMTokenGenerator {
    private static final Logger logger = LoggerFactory.getLogger(DMTokenGenerator.class);

    private static final String defaultAlgorithm = "SHA1withRSA";
    private final String algorithm;

    private PrivateKey key;
    private byte[] token; // Token to use

    public DMTokenGenerator(PrivateKey key, String algorithm) {
        this.key = key;
        this.algorithm = algorithm;
    }

    public DMTokenGenerator(PrivateKey key) {
        this(key, defaultAlgorithm);
    }

    CommandAPDU applyToken(CommandAPDU apdu) throws GeneralSecurityException {
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        try {
            newData.write(apdu.getData());

            if (key == null) {
                logger.trace("No private key for token generation provided");
                if (apdu.getINS() != (INS_DELETE & 0xFF))
                    newData.write(0); // No token
            } else {
                if (apdu.getINS() == (INS_DELETE & 0xFF)) {
                    // See GP 2.3.1 Table 11-23
                    logger.trace("Adding tag 0x9E before Delete Token");
                    newData.write(0x9E);
                }
                logger.trace("Using private key for token generation (" + algorithm + ")");
                byte[] token = calculateToken(apdu, key);
                newData.write(token.length);
                newData.write(token);
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not apply DM token", e);
        }
        return new CommandAPDU(apdu.getCLA(), apdu.getINS(), apdu.getP1(), apdu.getP2(), newData.toByteArray()); // FIXME: Le handling
    }

    private byte[] calculateToken(CommandAPDU apdu, PrivateKey key) throws GeneralSecurityException {
        return signData(key, getTokenData(apdu));
    }

    private static byte[] getTokenData(CommandAPDU apdu) {
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            bo.write(apdu.getP1());
            bo.write(apdu.getP2());
            bo.write(apdu.getData().length); // FIXME: length handling for > 255 bytes
            bo.write(apdu.getData());
            return bo.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Could not get P1/P2 or data for token calculation", e);
        }
    }

    private byte[] signData(PrivateKey privateKey, byte[] apduData) throws GeneralSecurityException {
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(privateKey);
        signer.update(apduData);
        byte[] signature = signer.sign();
        logger.info("Generated DM token: {}" + HexUtils.bin2hex(signature));
        return signature;
    }

    public boolean hasKey() {
        return key != null;
    }
}
