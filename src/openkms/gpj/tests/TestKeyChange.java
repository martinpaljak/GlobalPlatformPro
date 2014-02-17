package openkms.gpj.tests;

import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.CardException;

import openkms.gpj.GPException;
import openkms.gpj.GlobalPlatform;
import openkms.gpj.GlobalPlatformData;
import openkms.gpj.KeySet;
import openkms.gpj.KeySet.KeyDiversification;

import org.junit.Test;

public class TestKeyChange extends TestRealCard {

	public static byte[] newKey = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F };

	@Test
	public void testAddNewWithDefault() throws CardException, GPException {
		gp.openSecureChannel(new KeySet(GlobalPlatformData.defaultKey), GlobalPlatform.SCP_ANY, gp.defaultMode);

		List<KeySet.Key> keys = new ArrayList<KeySet.Key>();
		// Version 1, id 1
		keys.add(new KeySet.Key(01, 01, newKey));
		keys.add(new KeySet.Key(01, 02, newKey));
		keys.add(new KeySet.Key(01, 03, newKey));

		GlobalPlatformData.print_card_info(gp);
		gp.putKeys(keys, false);
		GlobalPlatformData.print_card_info(gp);
	}

	@Test
	public void testReplaceNewWithDefault() throws CardException, GPException {
		gp.openSecureChannel(new KeySet(TestKeyChange.newKey), GlobalPlatform.SCP_ANY, gp.defaultMode);

		List<KeySet.Key> keys = new ArrayList<KeySet.Key>();
		keys.add(new KeySet.Key(01, 01, GlobalPlatformData.defaultKey));
		keys.add(new KeySet.Key(01, 02, GlobalPlatformData.defaultKey));
		keys.add(new KeySet.Key(01, 03, GlobalPlatformData.defaultKey));

		GlobalPlatformData.print_card_info(gp);
		gp.putKeys(keys, true);
		GlobalPlatformData.print_card_info(gp);
	}

	@Test
	public void testReplaceDefaultWithNew() throws CardException, GPException {
		gp.openSecureChannel(new KeySet(GlobalPlatformData.defaultKey, KeyDiversification.EMV), GlobalPlatform.SCP_ANY, gp.defaultMode);
		List<KeySet.Key> keys = new ArrayList<KeySet.Key>();

		keys.add(new KeySet.Key(01, 01, TestKeyChange.newKey));
		keys.add(new KeySet.Key(01, 02, TestKeyChange.newKey));
		keys.add(new KeySet.Key(01, 03, TestKeyChange.newKey));
		GlobalPlatformData.print_card_info(gp);
		gp.putKeys(keys, true);
		GlobalPlatformData.print_card_info(gp);
	}

}
