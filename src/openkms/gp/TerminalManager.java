/*
 * Copyright (c) 2014 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package openkms.gp;

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

	private static final String debian_path = "/usr/lib/libpcsclite.so.1";
	private static final String ubuntu_path = "/lib/libpcsclite.so.1";

	private static boolean buggy = true;

	public static TerminalFactory getTerminalFactory() throws NoSuchAlgorithmException {
		// Set necessary parameters for seamless PC/SC access. OpenJDK has wrong
		// paths (without .1) See this blog post:
		// http://ludovicrousseau.blogspot.com.es/2013/03/oracle-javaxsmartcardio-failures.html
		if (System.getProperty("os.name").equalsIgnoreCase("Linux")) {
			if (new File(debian_path).exists()) {
				System.setProperty("sun.security.smartcardio.library", debian_path);
			} else if (new File(ubuntu_path).exists()) {
				System.setProperty("sun.security.smartcardio.library", ubuntu_path);
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
	 * The parameter is fixed based on the used provider and assumes that written code is correct.
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
				throw new RuntimeException("This application expects one and only one card reader (with an inserted card)");
			} else {
				return tl.list().get(0);
			}
		} catch (NoSuchAlgorithmException e) {
			throw new CardException(e);
		}
	}

	// Given an instance of some Exception from a PC/SC system,
	// return a meaningful PC/SC error name.
	public static String getExceptionMessage(Exception e) {
		if (e instanceof CardException) {
			// This comes from SunPCSC most probably and already contains the PC/SC error in the cause
			if (e.getCause() != null) {
				if (e.getCause().getMessage() != null) {
					if (e.getCause().getMessage().indexOf("SCARD_") != -1) {
						return e.getCause().getMessage();
					}
				}
			}
		}
		if (e.getClass().getCanonicalName().equalsIgnoreCase("jnasmartcardio.Smartcardio.EstablishContextException")) {
			if (e.getCause().getMessage().indexOf("SCARD_E_NO_SERVICE") != -1)
				return "SCARD_E_NO_SERVICE";
		}
		return null;
	}
}
