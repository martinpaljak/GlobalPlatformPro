// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.apdulette.MiseEnPlaceChef;
import apdu4j.core.HexUtils;
import apdu4j.prefs.Preferences;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPDataException;
import org.testng.annotations.Test;

import java.util.EnumSet;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static pro.javacard.gp.ng.GlobalPlatformCookbook.BLOCK_SIZE;

// Test recipes via MiseEnPlaceChef - pure pre-computation, no I/O
public class TestMiseEnPlace {

    private final MiseEnPlaceChef chef = new MiseEnPlaceChef();
    private final Preferences prefs = new Preferences().with(BLOCK_SIZE, 255);

    @Test
    public void testDeleteAid() {
        final var aid = new AID("A000000151000000");
        final var result = chef.cook(GlobalPlatformCookbook.delete_aid(aid, false), prefs);
        assertEquals(result.getSW(), 0x9000);
    }

    @Test
    public void testDeleteAidWithDeps() {
        final var aid = new AID("A000000151000000");
        final var result = chef.cook(GlobalPlatformCookbook.delete_aid(aid, true), prefs);
        assertEquals(result.getSW(), 0x9000);
    }

    @Test
    public void testSetCardStatus() {
        final var result = chef.cook(GlobalPlatformCookbook.set_card_status(GPRegistryEntryNG.ISDLifeCycle.SECURED), prefs);
        assertEquals(result.getSW(), 0x9000);
    }

    @Test
    public void testSetAppletStatus() {
        final var aid = new AID("A000000151000000");
        final var result = chef.cook(GlobalPlatformCookbook.set_applet_status(aid, true), prefs);
        assertEquals(result.getSW(), 0x9000);
    }

    @Test
    public void testStoreDataBlocks() {
        final var blocks = List.of(
                HexUtils.hex2bin("0102030405"),
                HexUtils.hex2bin("0607080910")
        );
        final var result = chef.cook(GlobalPlatformCookbook.store_data_blocks(blocks, 0x00), prefs);
        assertEquals(result.getSW(), 0x9000);
    }

    @Test
    public void testDeleteKey() {
        final var result = chef.cook(GlobalPlatformCookbook.delete_key(1, null), prefs);
        assertEquals(result.getSW(), 0x9000);
    }

    @Test
    public void testInstallAndMakeSelectable() {
        final var pkg = new AID("A000000151000000");
        final var applet = new AID("A000000151535041");
        final var instance = new AID("A000000151535041");
        final var result = chef.cook(GlobalPlatformCookbook.install_and_make_selectable(
                pkg, applet, instance, EnumSet.noneOf(GPRegistryEntryNG.Privilege.class), new byte[0]), prefs);
        assertEquals(result.getSW(), 0x9000);
    }

    // init_update needs real card data - MiseEnPlaceChef feeds empty 9000, parsing fails
    @Test(expectedExceptions = GPDataException.class)
    public void testInitUpdateFailsWithMockData() {
        chef.cook(GlobalPlatformCookbook.init_update(0, 0, HexUtils.hex2bin("0102030405060708")), prefs);
    }

    // Load blocks (multi-command batch with expectations)
    @Test
    public void testLoadBlocks() {
        final var loadBlock = HexUtils.hex2bin("C4" + "04" + "DEADBEEF");
        final var result = chef.cook(GlobalPlatformCookbook.load(loadBlock), prefs);
        assertEquals(result.getSW(), 0x9000);
    }
}
