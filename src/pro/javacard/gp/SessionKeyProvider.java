package pro.javacard.gp;


public interface SessionKeyProvider {
	GPKeySet getSessionKeys(int scp, byte[] kdd, byte[] ... args) throws GPException;
	int getKeysetVersion();
	int getKeysetID();
}
