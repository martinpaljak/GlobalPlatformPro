package pro.javacard.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CommandAPDU;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Signature;

public class DMTokenGenerator {
    private static final Logger logger = LoggerFactory.getLogger(DMTokenGenerator.class);
    private static final String acceptedSignatureAlgorithm = "SHA1withRSA";

    private PrivateKey key;

    public DMTokenGenerator(PrivateKey key) {
        this.key = key;
    }

    public CommandAPDU applyToken(CommandAPDU apdu) {
        ByteArrayOutputStream newData = new ByteArrayOutputStream();

        try {
            newData.write(apdu.getData());
            if (key == null) {
                logger.debug("No private key for token generation provided");
                newData.write(0); //Token length
            } else {
                logger.debug("Using private key for token generation (" + acceptedSignatureAlgorithm + ")");
                byte[] token = calculateToken(apdu, key);
                newData.write(token.length);
                newData.write(token);
            }
            return new CommandAPDU(apdu.getCLA(), apdu.getINS(), apdu.getP1(), apdu.getP2(), newData.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Could not add DM token to constructed APDU", e);
        }
    }

    private static byte[] calculateToken(CommandAPDU apdu, PrivateKey key) {
        return signData(key, getTokenData(apdu));
    }

    private static byte[] getTokenData(CommandAPDU apdu) {
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            bo.write(apdu.getP1());
            bo.write(apdu.getP2());
            bo.write(apdu.getData().length);
            bo.write(apdu.getData());
            return bo.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Could not get P1/P2 or data for token calculation", e);
        }
    }

    private static byte[] signData(PrivateKey privateKey, byte[] apduData) {
        try {
            Signature signature = Signature.getInstance(acceptedSignatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(apduData);
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException("Could not create signature with instance " + acceptedSignatureAlgorithm, e);
        }
    }

    public boolean hasKey() {
        return key != null;
    }

}
