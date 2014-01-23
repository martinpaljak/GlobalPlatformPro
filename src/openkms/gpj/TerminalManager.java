package openkms.gpj;

import java.io.File;
import java.security.NoSuchAlgorithmException;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

public class TerminalManager {

	private static boolean buggy = true;

	public static TerminalFactory getTerminalFactory() throws NoSuchAlgorithmException {
		// Set necessary parameters for seamless PC/SC access. OpenJDK has wrong
		// paths (without .1) See this blog post:
		// http://ludovicrousseau.blogspot.com.es/2013/03/oracle-javaxsmartcardio-failures.html
		if (System.getProperty("os.name").equalsIgnoreCase("Linux")) {
			if (new File("/usr/lib/libpcsclite.so.1").exists()) {
				// Debian
				System.setProperty("sun.security.smartcardio.library", "/usr/lib/libpcsclite.so.1");
			} else if (new File("/lib/libpcsclite.so.1").exists()) {
				// Ubuntu
				System.setProperty("sun.security.smartcardio.library", "/lib/libpcsclite.so.1");
			}
		}

		TerminalFactory tf = TerminalFactory.getDefault();
		// OSX is horribly broken. Use JNA based approach if not already
		// installed and used as default
		if (System.getProperty("os.name").equalsIgnoreCase("Mac OS X")) {
			if (tf.getProvider().getName() != jnasmartcardio.Smartcardio.PROVIDER_NAME) {
				tf = TerminalFactory.getInstance("PC/SC", null, new jnasmartcardio.Smartcardio());
			}
		}
		
		if (tf.getProvider().getName() == jnasmartcardio.Smartcardio.PROVIDER_NAME) {
			buggy = false;
		}
		return tf;
	}

	public static void disconnect(Card card, boolean reset) throws CardException {
		card.disconnect(buggy ? !reset : reset);
	}

	public static CardTerminal getTheReader() throws CardException {
		try {
			TerminalFactory tf = getTerminalFactory();
			CardTerminals tl = tf.terminals();
			if (tl.list().size() != 1) {
				throw new RuntimeException("Need to have one and only one reader.");
			}
			return tl.list().get(0);
		} catch (NoSuchAlgorithmException e) {
			throw new CardException(e);
		}
	}
}
