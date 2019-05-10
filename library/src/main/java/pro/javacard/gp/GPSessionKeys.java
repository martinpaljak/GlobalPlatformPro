package pro.javacard.gp;

import apdu4j.HexUtils;

import java.security.GeneralSecurityException;

import static pro.javacard.gp.GPCardKeys.KeyPurpose;

public class GPSessionKeys {
    GPCardKeys cardKeys;

    private final byte[] enc;
    private final byte[] mac;
    private final byte[] rmac;


    public GPSessionKeys(GPCardKeys cardKeys, byte[] enc, byte[] mac, byte[] rmac) {
        this.cardKeys = cardKeys;
        this.enc = enc;
        this.mac = mac;
        this.rmac = rmac;
    }

    // Encrypts, either with session DEK (SCP02) or card DEK (SCP01 and SCP03)
    public byte[] encrypt(byte[] data) {
        return cardKeys.encrypt(data);
    }

    public byte[] encryptKey(GPCardKeys other, GPCardKeys.KeyPurpose p) throws GeneralSecurityException {
        return cardKeys.encryptKey(other, p);
    }

    public byte[] getKeyFor(KeyPurpose p) {
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
        return String.format("ENC=%s MAC=%s, card keys=%s", HexUtils.bin2hex(enc), HexUtils.bin2hex(mac), cardKeys.toString());
    }
}
