// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.apdulette.Chef;
import apdu4j.core.BIBOSA;
import apdu4j.core.DumpFormat;
import apdu4j.core.HexUtils;
import apdu4j.core.MockBIBO;
import pro.javacard.gp.GPDataException;
import pro.javacard.gp.GPSession;
// PlaintextKeys import removed - using PlaintextCardKeys
import org.testng.annotations.Test;

import java.util.EnumSet;

import static org.testng.Assert.*;

public class TestGlobalPlatformCookbook {

    // Helper to create Chef from a classpath dump resource
    private Chef chef_from_dump(final String resource) {
        final var dump = DumpFormat.parse(getClass().getResourceAsStream(resource));
        final var mock = MockBIBO.fromDump(dump);
        return Chef.of(mock);
    }

    @Test
    public void testParseInitUpdateScp03() {
        final var response = HexUtils.hex2bin("00003244342976208448010370734ECDCA19E446A30BC253BCE97DB991000436");
        final var hostChallenge = HexUtils.hex2bin("0102030405060708");
        final var parsed = InitUpdateResponse.parse(response, hostChallenge);

        assertEquals(HexUtils.bin2hex(parsed.diversificationData()), "00003244342976208448");
        assertEquals(parsed.keyVersion(), 1);
        assertEquals(parsed.scp(), 3);
        assertEquals(parsed.scpI(), Integer.valueOf(0x70));
        assertFalse(parsed.s16());
        assertEquals(HexUtils.bin2hex(parsed.cardChallenge()), "734ECDCA19E446A3");
        assertEquals(HexUtils.bin2hex(parsed.cardCryptogram()), "0BC253BCE97DB991");
        assertNotNull(parsed.sequenceCounter());
        assertEquals(HexUtils.bin2hex(parsed.sequenceCounter()), "000436");
        assertEquals(HexUtils.bin2hex(parsed.hostChallenge()), "0102030405060708");
    }

    @Test
    public void testInitUpdateRecipeFromDump() {
        final var chef = chef_from_dump("/scp03-init-update-jcop4.dump");
        final var parsed = chef.cook(GlobalPlatformCookbook.init_update(0, 0, HexUtils.hex2bin("0102030405060708")));

        assertEquals(parsed.scp(), 3);
        assertEquals(parsed.keyVersion(), 1);
        assertEquals(HexUtils.bin2hex(parsed.diversificationData()), "00003244342976208448");
        assertFalse(parsed.s16());
    }

    @Test
    public void testOpenSecureChannelFromDump() {
        final var dump = DumpFormat.parse(getClass().getResourceAsStream("/scp03-auth-jcop4.dump"));
        final var mock = MockBIBO.fromDump(dump);
        final var chef = Chef.of(mock);
        final var keys = PlaintextCardKeys.defaultKey();
        final var mode = EnumSet.of(GPSession.APDUMode.MAC);
        final var fixedChallenge = HexUtils.hex2bin("0102030405060708");

        final var state = chef.cook(GlobalPlatformCookbook.open_secure_channel(keys, mode, fixedChallenge));
        assertNotNull(state);
        assertTrue(state instanceof SCP03.State);

        // Verify we can wrap a GET STATUS through the secure channel
        final var scpBibosa = SCP03.secure(new BIBOSA(mock), (SCP03.State) state);
        final var secureChef = Chef.of(scpBibosa);
        final var registry = secureChef.cook(GlobalPlatformCookbook.get_status(0x80));
        assertTrue(registry.length > 0);
    }

    @Test
    public void testParseInitUpdateScp01() {
        final var response = HexUtils.hex2bin("00008359017652074673FF0163A28A974047A95AE4B396BD96866D06");
        final var hostChallenge = HexUtils.hex2bin("C0F8AE055C5AB83B");
        final var parsed = InitUpdateResponse.parse(response, hostChallenge);

        assertEquals(HexUtils.bin2hex(parsed.diversificationData()), "00008359017652074673");
        assertEquals(parsed.keyVersion(), 0xFF);
        assertEquals(parsed.scp(), 1);
        assertNull(parsed.scpI());
        assertFalse(parsed.s16());
        assertEquals(HexUtils.bin2hex(parsed.cardChallenge()), "63A28A974047A95A");
        assertEquals(HexUtils.bin2hex(parsed.cardCryptogram()), "E4B396BD96866D06");
        assertNull(parsed.sequenceCounter());
        assertEquals(HexUtils.bin2hex(parsed.hostChallenge()), "C0F8AE055C5AB83B");
    }

    @Test
    public void testOpenSecureChannelScp01FromDump() {
        final var dump = DumpFormat.parse(getClass().getResourceAsStream("/scp01-auth.dump"));
        final var mock = MockBIBO.fromDump(dump);
        final var chef = Chef.of(mock);
        final var keys = PlaintextCardKeys.defaultKey();
        final var mode = EnumSet.of(GPSession.APDUMode.MAC);
        final var fixedChallenge = HexUtils.hex2bin("C0F8AE055C5AB83B");

        final var state = chef.cook(GlobalPlatformCookbook.open_secure_channel(keys, mode, fixedChallenge));
        assertNotNull(state);
        assertTrue(state instanceof SCP01.State);

        // Verify we can wrap a GET STATUS through the secure channel and get a valid response
        final var scpBibosa = SCP01.secure(new BIBOSA(mock), (SCP01.State) state);
        final var secureChef = Chef.of(scpBibosa);
        final var registry = secureChef.cook(GlobalPlatformCookbook.get_status(0x80));
        assertTrue(registry.length > 0);
    }

    @Test
    public void testParseInitUpdateScp02() {
        final var response = HexUtils.hex2bin("00008147580F3D2988D8FF020005BD1A6BE9D3D575BD9E5774FB6A25");
        final var hostChallenge = HexUtils.hex2bin("796B87A024C3EF57");
        final var parsed = InitUpdateResponse.parse(response, hostChallenge);

        assertEquals(HexUtils.bin2hex(parsed.diversificationData()), "00008147580F3D2988D8");
        assertEquals(parsed.keyVersion(), 0xFF);
        assertEquals(parsed.scp(), 2);
        assertNull(parsed.scpI());
        // SCP02: seq counter is separate, card challenge is 6 bytes after seq
        assertNotNull(parsed.sequenceCounter());
        assertEquals(HexUtils.bin2hex(parsed.sequenceCounter()), "0005");
        assertEquals(HexUtils.bin2hex(parsed.cardChallenge()), "BD1A6BE9D3D5");
        assertEquals(HexUtils.bin2hex(parsed.cardCryptogram()), "75BD9E5774FB6A25");
    }

    @Test
    public void testOpenSecureChannelScp02FromDump() {
        final var dump = DumpFormat.parse(getClass().getResourceAsStream("/scp02-auth.dump"));
        final var mock = MockBIBO.fromDump(dump);
        final var chef = Chef.of(mock);
        final var keys = PlaintextCardKeys.defaultKey();
        final var mode = EnumSet.of(GPSession.APDUMode.MAC);
        final var fixedChallenge = HexUtils.hex2bin("796B87A024C3EF57");

        final var state = chef.cook(GlobalPlatformCookbook.open_secure_channel(keys, mode, fixedChallenge));
        assertNotNull(state);
        assertTrue(state instanceof SCP02.State);

        // Verify we can wrap a GET STATUS through the secure channel
        final var scpBibosa = SCP02.secure(new BIBOSA(mock), (SCP02.State) state);
        final var secureChef = Chef.of(scpBibosa);
        final var registry = secureChef.cook(GlobalPlatformCookbook.get_status(0x80));
        assertTrue(registry.length > 0);
    }

    @Test(expectedExceptions = GPDataException.class)
    public void testParseInitUpdateScp03TooShort() {
        final var response = HexUtils.hex2bin("0000324434297620844801");
        InitUpdateResponse.parse(response, HexUtils.hex2bin("0102030405060708"));
    }
}
