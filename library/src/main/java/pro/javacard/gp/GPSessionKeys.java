package pro.javacard.gp;

import apdu4j.HexUtils;
import pro.javacard.gp.GPCardKeys.KeyPurpose;

import java.security.GeneralSecurityException;

public class GPSessionKeys {
    GPCardKeys cardKeys;

    private final byte[] enc;
    private final byte[] mac;
    private final byte[] rmac;


    public GPSessionKeys(GPCardKeys cardKeys, byte[] enc, byte[] mac, byte[] rmac) {
        this.cardKeys = cardKeys;
        this.enc = enc.clone();
        this.mac = mac.clone();
        if (rmac == null)
            this.rmac = new byte[0];
        else
            this.rmac = rmac.clone();
    }

    // Encrypts padded data, either with session DEK (SCP02) or card DEK (SCP01 and SCP03)
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        return cardKeys.encrypt(data);
    }

    public byte[] encryptKey(GPCardKeys other, KeyPurpose p) throws GeneralSecurityException {
        return cardKeys.encryptKey(other, p);
    }

    public byte[] get(KeyPurpose p) {
        switch (p) {
            case ENC:
                return enc.clone();
            case MAC:
                return mac.clone();
            case RMAC:
                return rmac.clone();
            default:
                throw new IllegalArgumentException("Invalid session key: " + p);
        }
    }

    @Override
    public String toString() {
        return String.format("ENC=%s MAC=%s RMAC=%s, card keys=%s", HexUtils.bin2hex(enc), HexUtils.bin2hex(mac), rmac == null ? "N/A" : HexUtils.bin2hex(rmac), cardKeys.toString());
    }
}
