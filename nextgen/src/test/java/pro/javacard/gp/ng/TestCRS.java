// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.apdulette.SousChef;
import apdu4j.core.DumpFormat;
import apdu4j.core.HexUtils;
import apdu4j.core.MockBIBO;
import org.testng.annotations.Test;
import pro.javacard.capfile.AID;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVParseException;
import pro.javacard.tlv.TLVs;
import pro.javacard.tlv.Tag;

import java.util.List;

import static org.testng.Assert.*;

// Test the Amendment C CRS response parsers
public class TestCRS {

    @Test
    public void testParseStatusTwoEntries() {
        // Two 61 templates: 4F (AID) + 9F70 (lifecycle, contactless state)
        // First app ACTIVATED (01), second DEACTIVATED (00)
        var data = HexUtils.hex2bin(
                "610C4F05D2450077009F70020701"
              + "610C4F05A0000001519F70020700");

        var entries = GlobalPlatformCookbook.parse_crs_status(data);
        assertEquals(entries.size(), 2);

        assertEquals(entries.get(0).aid().toString(), "D245007700");
        assertEquals(entries.get(0).lifecycle(), 0x07);
        assertEquals(entries.get(0).clState(), GlobalPlatformCookbook.CRSEntry.ACTIVATED);

        assertEquals(entries.get(1).aid().toString(), "A000000151");
        assertEquals(entries.get(1).lifecycle(), 0x07);
        assertEquals(entries.get(1).clState(), GlobalPlatformCookbook.CRSEntry.DEACTIVATED);
    }

    @Test
    public void testParseStatusWithCrel() {
        // One 61 record carrying an A4 CREL list (two 4F AIDs), one without.
        // Built with the TLV library so the lengths are computed, not hand-written.
        var withCrel = TLV.of(Tag.ber(0x61), List.of(
                TLV.of(Tag.ber(0x4F), HexUtils.hex2bin("D245007700")),
                TLV.of(Tag.ber(0x9F, 0x70), HexUtils.hex2bin("0701")),
                TLV.of(Tag.ber(0xA4), List.of(
                        TLV.of(Tag.ber(0x4F), HexUtils.hex2bin("A000000151")),
                        TLV.of(Tag.ber(0x4F), HexUtils.hex2bin("A00000015143525300"))))));
        var plain = TLV.of(Tag.ber(0x61), List.of(
                TLV.of(Tag.ber(0x4F), HexUtils.hex2bin("A000000151")),
                TLV.of(Tag.ber(0x9F, 0x70), HexUtils.hex2bin("0700"))));
        var data = TLVs.of(withCrel, plain).encode();

        var entries = GlobalPlatformCookbook.parse_crs_status(data);
        assertEquals(entries.size(), 2);
        // The first entry exposes its referenced CREL AIDs, in order
        assertEquals(entries.get(0).aid().toString(), "D245007700");
        assertEquals(entries.get(0).crelList().size(), 2);
        assertEquals(entries.get(0).crelList().get(0).toString(), "A000000151");
        assertEquals(entries.get(0).crelList().get(1).toString(), "A00000015143525300");
        // Absent A4 yields an empty list, not an error
        assertTrue(entries.get(1).crelList().isEmpty());
    }

    @Test
    public void testParseInfoBare() {
        // A5 { 9F08 version = 0100, 80 counter = 0005 }
        var data = HexUtils.hex2bin("A5099F0802010080020005");
        var info = GlobalPlatformCookbook.parse_crs_info(data);
        assertEquals(info.version(), 0x0100);
        assertEquals(info.counter(), 5);
    }

    @Test
    public void testParseInfoRejectsFci() {
        // parse_crs_info handles only the bare GET DATA(A5) response (GPC 2.3 Contactless, Table 3-32).
        // A 6F-wrapped SELECT FCI (no top-level A5) is parse_fci's job and must not be accepted here.
        var data = HexUtils.hex2bin("6F1684" + "09A00000015143525300"
                + "A5099F0802010080020005");
        assertThrows(TLVParseException.class, () -> GlobalPlatformCookbook.parse_crs_info(data));
    }

    @Test
    public void testParseFailuresA1() {
        // A1 failed-list carrying two 4F AIDs
        var data = HexUtils.hex2bin("A10E4F05D2450077004F05A000000151");
        var aids = GlobalPlatformCookbook.parse_crs_failures(data);
        assertEquals(aids.size(), 2);
        assertEquals(aids.get(0).toString(), "D245007700");
        assertEquals(aids.get(1).toString(), "A000000151");
    }

    @Test
    public void testParseFailures61() {
        // 61 template carrying two 4F AIDs
        var data = HexUtils.hex2bin("610E4F05D2450077004F05A000000151");
        var aids = GlobalPlatformCookbook.parse_crs_failures(data);
        assertEquals(aids.size(), 2);
        assertEquals(aids.get(0).toString(), "D245007700");
        assertEquals(aids.get(1).toString(), "A000000151");
    }

    // --- Replay tests against real-card captures (resources/crs-*.dump, captured with `gp --ng ... --dump`) ---
    // Each dump is the exact SELECT + command exchange gp sent to a live card; the recipes are
    // cooked in the same order so MockBIBO's command verification confirms the wire bytes too.

    private SousChef chef_from_dump(final String resource) {
        final var dump = DumpFormat.parse(getClass().getResourceAsStream(resource));
        return new SousChef(MockBIBO.fromDump(dump));
    }

    // The application toggled across the set-status dumps.
    private static final AID TARGET = AID.fromString("A000000003143117140617005643");

    @Test
    public void testCrsInfoFromDump() {
        final var chef = chef_from_dump("/crs-info.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(GlobalPlatformCookbook.CRS_AID));
        final var info = chef.cook(GlobalPlatformCookbook.crs_get_data());
        assertEquals(info.version(), 0x0100);
        assertEquals(info.counter(), 31);
    }

    @Test
    public void testCrsListFromDump() {
        final var chef = chef_from_dump("/crs-list.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(GlobalPlatformCookbook.CRS_AID));
        // Plain listing (no 5C tag list); MockBIBO verifies the 4F00 wire command.
        final var entries = chef.cook(GlobalPlatformCookbook.crs_get_status(new byte[0], false));
        assertEquals(entries.size(), 6);
        // First entry: the Card Manager / ISD
        assertEquals(entries.get(0).aid().toString(), "A000000151000000");
        assertEquals(entries.get(0).lifecycle(), 0x0F);
        assertEquals(entries.get(0).clState(), GlobalPlatformCookbook.CRSEntry.ACTIVATED);
        // The CRS itself appears in its own listing
        assertEquals(entries.get(1).aid().toString(), "A00000015143525300");
        // The toggled application, activated in this capture
        assertEquals(entries.get(4).aid().toString(), "A000000003143117140617005643");
        assertEquals(entries.get(4).clState(), GlobalPlatformCookbook.CRSEntry.ACTIVATED);
    }

    @Test
    public void testCrsListVerboseFromDump() {
        final var chef = chef_from_dump("/crs-list-crel.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(GlobalPlatformCookbook.CRS_AID));
        // Verbose listing adds 5C 04 4F 9F70 A4; MockBIBO verifies that exact wire command.
        final var entries = chef.cook(GlobalPlatformCookbook.crs_get_status(new byte[0], true));
        assertEquals(entries.size(), 6);
        assertEquals(entries.get(0).aid().toString(), "A000000151000000");
        assertEquals(entries.get(4).aid().toString(), "A000000003143117140617005643");
        // This card carries no CREL references, so every crelList is empty (no A4 returned).
        assertTrue(entries.stream().allMatch(e -> e.crelList().isEmpty()));
    }

    @Test
    public void testCrsDeactivateFromDump() {
        final var chef = chef_from_dump("/crs-deactivate.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(GlobalPlatformCookbook.CRS_AID));
        final var failed = chef.cook(GlobalPlatformCookbook.crs_set_status(List.of(TARGET), false));
        assertTrue(failed.isEmpty());
    }

    @Test
    public void testCrsActivateFromDump() {
        final var chef = chef_from_dump("/crs-activate.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(GlobalPlatformCookbook.CRS_AID));
        final var failed = chef.cook(GlobalPlatformCookbook.crs_set_status(List.of(TARGET), true));
        assertTrue(failed.isEmpty());
    }
}
