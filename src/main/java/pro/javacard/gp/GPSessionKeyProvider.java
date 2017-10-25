package pro.javacard.gp;

// Provides a interface for session keys. Session keys are derived from card keys
// Session keys are PLAINTEXT keys.
// Providers are free to derive session keys based on hardware backed master keys
// PlaintextKeys provides card keys, that are ... plaintext (not backed by hardware)

public abstract class GPSessionKeyProvider {

    // returns true if keys can probably be made
    public abstract boolean init(byte[] atr, byte[] cplc, byte[] kinfo);

    // Any can be null, if N/A for SCP version
    public abstract void calculate(int scp, byte[] kdd, byte[] host_challenge, byte[] card_challenge, byte[] ssc) throws GPException;

    public abstract GPKey getKeyFor(KeyPurpose p);

    public abstract int getID();

    public abstract int getVersion();

    // Session keys are used for various purposes
    public enum KeyPurpose {
        // ID is as used in diversification/derivation
        // That is - one based.
        ENC(1), MAC(2), DEK(3), RMAC(4);

        private final int value;

        KeyPurpose(int value) {
            this.value = value;
        }

        public byte getValue() {
            return (byte) (value & 0xFF);
        }
    }

}
