// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.core.BIBOSA;
import apdu4j.core.BIBOException;
import apdu4j.core.HexUtils;
import apdu4j.core.MockBIBO;
import apdu4j.core.StatefulBIBO;
import apdu4j.prefs.Preferences;
import org.testng.annotations.Test;
import pro.javacard.gp.GPSession;

import java.util.EnumSet;

import static org.testng.Assert.*;
import static pro.javacard.gp.ng.GlobalPlatformCookbook.BLOCK_SIZE;

public class TestSecureChannels {

    // SCP03: failed transceive with ENC must not increment counter
    @Test
    public void testSCP03ErrorRecoveryPreservesState() {
        final var keys = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");
        final var session = new SCP03.State(keys, keys, keys, new byte[16],
                EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC), false);
        final var mock = MockBIBO.throwing();
        final var bibosa = SCP03.secure(new BIBOSA(mock), session);

        final var stateful = (StatefulBIBO<?>) bibosa.bibo();
        final var stateBefore = (SCP03.State) stateful.state();
        assertEquals(stateBefore.counter(), 0);

        // Wrap would increment counter for ENC, but failed send must roll back
        try {
            bibosa.transceive(HexUtils.hex2bin("80F28002044F00000000"));
            fail("Expected BIBOException");
        } catch (BIBOException e) {
            // expected
        }

        assertSame(stateful.state(), stateBefore);
        assertEquals(((SCP03.State) stateful.state()).counter(), 0);
    }

    // Key zeroing via close()
    @Test
    public void testKeyZeroingOnClose() {
        final var encKey = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");
        final var macKey = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");
        final var rmacKey = HexUtils.hex2bin("404142434445464748494A4B4C4D4E4F");
        final var session = new SCP03.State(encKey, macKey, rmacKey, new byte[16],
                EnumSet.of(GPSession.APDUMode.MAC), false);
        final var mock = MockBIBO.of();
        final var bibosa = SCP03.secure(new BIBOSA(mock), session);

        // Keys from session accessors are what the factory received
        final var stateful = (StatefulBIBO<?>) bibosa.bibo();
        final var state = (SCP03.State) stateful.state();

        // Verify keys are non-zero before close
        assertNotEquals(state.encKey()[0], (byte) 0);

        bibosa.close();

        // Verify keys are zeroed after close
        for (var b : state.encKey()) {
            assertEquals(b, (byte) 0);
        }
        for (var b : state.macKey()) {
            assertEquals(b, (byte) 0);
        }
        for (var b : state.rmacKey()) {
            assertEquals(b, (byte) 0);
        }
    }

    // Block size computation: SCP01 MAC only
    @Test
    public void testBlockSizeSCP01Mac() {
        final var session = new SCP01.State(new byte[16], new byte[16], new byte[8],
                EnumSet.of(GPSession.APDUMode.MAC));
        final var mock = MockBIBO.of();
        final var stack = new BIBOSA(mock, new Preferences().with(BLOCK_SIZE, 255));
        final var bibosa = SCP01.secure(stack, session);
        assertEquals(bibosa.preferences().get(BLOCK_SIZE), 255 - 8);
    }

    // Block size computation: SCP01 MAC + ENC
    @Test
    public void testBlockSizeSCP01MacEnc() {
        final var session = new SCP01.State(new byte[16], new byte[16], new byte[8],
                EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
        final var mock = MockBIBO.of();
        final var stack = new BIBOSA(mock, new Preferences().with(BLOCK_SIZE, 255));
        final var bibosa = SCP01.secure(stack, session);
        // (255 - 8) / 8 * 8 - 2 = 247/8*8 - 2 = 30*8 - 2 = 240 - 2 = 238
        assertEquals(bibosa.preferences().get(BLOCK_SIZE), 238);
    }

    // Block size computation: SCP02 MAC only
    @Test
    public void testBlockSizeSCP02Mac() {
        final var session = new SCP02.State(new byte[16], new byte[16], new byte[16], new byte[8],
                EnumSet.of(GPSession.APDUMode.MAC));
        final var mock = MockBIBO.of();
        final var stack = new BIBOSA(mock, new Preferences().with(BLOCK_SIZE, 255));
        final var bibosa = SCP02.secure(stack, session);
        assertEquals(bibosa.preferences().get(BLOCK_SIZE), 255 - 8);
    }

    // Block size computation: SCP02 MAC + ENC
    @Test
    public void testBlockSizeSCP02MacEnc() {
        final var session = new SCP02.State(new byte[16], new byte[16], new byte[16], new byte[8],
                EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
        final var mock = MockBIBO.of();
        final var stack = new BIBOSA(mock, new Preferences().with(BLOCK_SIZE, 255));
        final var bibosa = SCP02.secure(stack, session);
        // (255 - 8) / 8 * 8 - 1 = 247/8*8 - 1 = 30*8 - 1 = 240 - 1 = 239
        assertEquals(bibosa.preferences().get(BLOCK_SIZE), 239);
    }

    // Block size computation: SCP03 MAC S8
    @Test
    public void testBlockSizeSCP03MacS8() {
        final var session = new SCP03.State(new byte[16], new byte[16], new byte[16], new byte[16],
                EnumSet.of(GPSession.APDUMode.MAC), false);
        final var mock = MockBIBO.of();
        final var stack = new BIBOSA(mock, new Preferences().with(BLOCK_SIZE, 255));
        final var bibosa = SCP03.secure(stack, session);
        assertEquals(bibosa.preferences().get(BLOCK_SIZE), 255 - 8);
    }

    // Block size computation: SCP03 MAC S16
    @Test
    public void testBlockSizeSCP03MacS16() {
        final var session = new SCP03.State(new byte[16], new byte[16], new byte[16], new byte[16],
                EnumSet.of(GPSession.APDUMode.MAC), true);
        final var mock = MockBIBO.of();
        final var stack = new BIBOSA(mock, new Preferences().with(BLOCK_SIZE, 255));
        final var bibosa = SCP03.secure(stack, session);
        assertEquals(bibosa.preferences().get(BLOCK_SIZE), 255 - 16);
    }

    // Block size computation: SCP03 MAC + ENC S8
    @Test
    public void testBlockSizeSCP03MacEncS8() {
        final var session = new SCP03.State(new byte[16], new byte[16], new byte[16], new byte[16],
                EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC), false);
        final var mock = MockBIBO.of();
        final var stack = new BIBOSA(mock, new Preferences().with(BLOCK_SIZE, 255));
        final var bibosa = SCP03.secure(stack, session);
        // (255 - 8) / 16 * 16 - 1 = 247/16*16 - 1 = 15*16 - 1 = 240 - 1 = 239
        assertEquals(bibosa.preferences().get(BLOCK_SIZE), 239);
    }

}
