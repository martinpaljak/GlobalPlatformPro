package openkms.gpj;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CardTerminals.State;
import javax.smartcardio.TerminalFactory;

/**
 * Facilitates working with javax.smartcardio
 *
 * @author Martin Paljak
 *
 */
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

		// Right now only JNA based approach should be correct.
		if (tf.getProvider().getName() == jnasmartcardio.Smartcardio.PROVIDER_NAME) {
			buggy = false;
		}
		return tf;
	}

	/**
	 * Calls {@link javax.smartcardio.Card#disconnect(boolean)} with the fixed reset parameter.
	 *
	 * The parameter is fixed based on the used provider.
	 *
	 * @param card The card on what to act
	 * @param reset The intended operation after disconnect
	 * @throws CardException
	 */
	public static void disconnect(Card card, boolean reset) throws CardException {
		card.disconnect(buggy ? !reset : reset);
	}

	public static CardTerminal getTheReader() throws CardException {
		try {
			TerminalFactory tf = getTerminalFactory();
			CardTerminals tl = tf.terminals();
			List<CardTerminal> list = tl.list(State.CARD_PRESENT);
			if (list.size() == 0) {
				// No readers with cards. Maybe empty readers?
				list = tl.list(State.ALL);
			}

			if (list.size() != 1) {
				throw new RuntimeException("This application expect one and only one card reader with an inserted card");
			} else {
				return tl.list().get(0);
			}
		} catch (NoSuchAlgorithmException e) {
			throw new CardException(e);
		}
	}
}
