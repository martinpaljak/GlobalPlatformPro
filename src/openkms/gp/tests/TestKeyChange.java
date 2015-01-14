package openkms.gp.tests;

import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.CardException;

import openkms.gp.GPData;
import openkms.gp.GPException;
import openkms.gp.GPKeySet;
import openkms.gp.GPKeySet.Diversification;
import openkms.gp.GPKeySet.GPKey;
import openkms.gp.GPKeySet.GPKey.Type;
import openkms.gp.GlobalPlatform;

import org.junit.Test;

public class TestKeyChange extends TestRealCard {

	public static byte[] newKey = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F };

	@Test
	public void testAddNewWithDefault() throws CardException, GPException {
		gp.openSecureChannel(new GPKeySet(new GPKey(GPData.defaultKey, GPKey.Type.DES3)), null, GlobalPlatform.SCP_ANY, gp.defaultMode);

		List<GPKeySet.GPKey> keys = new ArrayList<GPKeySet.GPKey>();
		GPKey nk = new GPKey(GPData.defaultKey, Type.DES3);
		// Version 1, id 1
		keys.add(new GPKey(01, 01, nk));
		keys.add(new GPKey(01, 02, nk));
		keys.add(new GPKey(01, 03, nk));

		GPData.print_card_info(gp);
		gp.putKeys(keys, false);
		GPData.print_card_info(gp);
	}

	@Test
	public void testReplaceNewWithDefault() throws CardException, GPException {
		gp.openSecureChannel(new GPKeySet(new GPKey(TestKeyChange.newKey, GPKey.Type.DES3)), null, GlobalPlatform.SCP_ANY, gp.defaultMode);

		List<GPKeySet.GPKey> keys = new ArrayList<GPKeySet.GPKey>();
		GPKey nk = new GPKey(GPData.defaultKey, Type.DES3);

		keys.add(new GPKeySet.GPKey(01, 01, nk));
		keys.add(new GPKeySet.GPKey(01, 02, nk));
		keys.add(new GPKeySet.GPKey(01, 03, nk));

		GPData.print_card_info(gp);
		gp.putKeys(keys, true);
		GPData.print_card_info(gp);
	}

	@Test
	public void testReplaceDefaultWithNew() throws CardException, GPException {
		gp.openSecureChannel(new GPKeySet(new GPKey(GPData.defaultKey, GPKey.Type.DES3), Diversification.EMV), null, GlobalPlatform.SCP_ANY, gp.defaultMode);
		List<GPKeySet.GPKey> keys = new ArrayList<GPKeySet.GPKey>();
		GPKey nk = new GPKey(TestKeyChange.newKey, Type.DES3);

		keys.add(new GPKeySet.GPKey(01, 01, nk));
		keys.add(new GPKeySet.GPKey(01, 02, nk));
		keys.add(new GPKeySet.GPKey(01, 03, nk));
		GPData.print_card_info(gp);
		gp.putKeys(keys, true);
		GPData.print_card_info(gp);
	}

}
