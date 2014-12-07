package openkms.gp;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactorySpi;

@SuppressWarnings("serial")
public class APDUReplayProvider extends Provider {
	private static final String PROVIDER_NAME = "APDUReplay";
	private static final String TERMINAL_NAME = "Replay Terminal";

	public APDUReplayProvider() {
		super(PROVIDER_NAME, 0.0d, "APDU Replay from javacard.pro");
		put("TerminalFactory.PC/SC", APDUReplayProviderSpi.class.getName());
	}

	public static class APDUReplayProviderSpi extends TerminalFactorySpi {
		InputStream script = null;
		List<byte[]> responses = null;
		public APDUReplayProviderSpi(Object parameter) {
			if (parameter != null && (parameter instanceof InputStream)) {
				script = (InputStream) parameter;
			}
		}

		@Override
		public CardTerminals engineTerminals() {
			return new ReplayTerminals(script);
		}

		public synchronized byte[] replay_transmit(byte[] cmd) throws CardException {
			// Just drop the command for now.
			if (responses.size() == 0)
				throw new CardException("Replay script depleted!");
			return responses.remove(0);
		}

		private final class ReplayTerminals extends CardTerminals {
			final Scanner script;
			private static final String PROTOCOL = "# PROTOCOL: ";
			private static final String ATR = "# ATR: ";

			ATR atr;
			String protocol;
			protected ReplayTerminals(InputStream script_stream) {
				script = new Scanner(script_stream);
				responses = new ArrayList<>();
				// Parse script file and fail to initiate if it can not be parsed
				while (script.hasNextLine()) {
					String l = script.nextLine().trim();
					// Skip comments

					if (l.startsWith("#")) {
						if (l.startsWith(ATR)) {
							atr = new ATR(GPUtils.stringToByteArray(l.substring(ATR.length())));
						} else if (l.startsWith(PROTOCOL)) {
							protocol = l.substring(PROTOCOL.length());
						}
						continue;
					}
					byte[] r = GPUtils.stringToByteArray(l);
					responses.add(r);
				}
				if (atr == null || protocol == null || responses.size() == 0)
					throw new RuntimeException("Incomplete APDU dump!");
			}

			@Override
			public List<CardTerminal> list(State state) throws CardException {
				ArrayList<CardTerminal> terminals = new ArrayList<CardTerminal>();
				if (state == State.ALL || state == State.CARD_PRESENT) {
					terminals.add(new ReplayTerminal());
				}
				return terminals;
			}

			@Override
			public boolean waitForChange(long arg0) throws CardException {
				return false;
			}

			private final class ReplayTerminal extends CardTerminal {
				@Override
				public Card connect(String protocol) throws CardException {
					return new ReplayCard();
				}

				@Override
				public String getName() {
					return TERMINAL_NAME;
				}

				@Override
				public boolean isCardPresent() throws CardException {
					return true;
				}

				@Override
				public boolean waitForCardAbsent(long arg0) throws CardException {
					return false;
				}

				@Override
				public boolean waitForCardPresent(long arg0) throws CardException {
					return true;
				}

				public final class ReplayCard extends Card {
					private final CardChannel basicChannel;
					protected ReplayCard() {
						basicChannel = new ReplayChannel();
					}

					@Override
					public void beginExclusive() throws CardException {
						// TODO Auto-generated method stub
						// This makes no sense as there is just this JVM instance
						// Maybe synchronize on transmit?
					}

					@Override
					public void disconnect(boolean reset) throws CardException {

					}

					@Override
					public void endExclusive() throws CardException {
						// TODO Auto-generated method stub
					}

					@Override
					public ATR getATR() {
						return atr;
					}

					@Override
					public CardChannel getBasicChannel() {
						return basicChannel;
					}

					@Override
					public String getProtocol() {
						return protocol;
					}

					@Override
					public CardChannel openLogicalChannel() throws CardException {
						throw new CardException("Logical channels not supported");
					}

					@Override
					public byte[] transmitControlCommand(int arg0, byte[] arg1) throws CardException {
						throw new RuntimeException("Control commands don't make sense");
					}


					public class ReplayChannel extends  CardChannel {

						@Override
						public void close() throws CardException {
							// As only basic logical channel is supported
							throw new IllegalStateException("Can't close basic channel");
						}

						@Override
						public Card getCard() {
							return ReplayCard.this;
						}

						@Override
						public int getChannelNumber() {
							return 0;
						}

						@Override
						public ResponseAPDU transmit(CommandAPDU apdu) throws CardException {
							return new ResponseAPDU(replay_transmit(apdu.getBytes()));
						}

						@Override
						public int transmit(ByteBuffer arg0, ByteBuffer arg1) throws CardException {
							byte[] cmd = new byte[arg0.remaining()];
							arg0.get(cmd);
							byte[] resp = replay_transmit(cmd);
							arg1.put(resp);
							return resp.length;
						}
					}
				}
			}
		}
	}
}

