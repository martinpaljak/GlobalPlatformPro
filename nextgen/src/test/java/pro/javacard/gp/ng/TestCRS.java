// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.apdulette.Chef;
import apdu4j.core.DumpFormat;
import apdu4j.core.HexUtils;
import apdu4j.core.MockBIBO;
import org.testng.annotations.Test;
import pro.javacard.capfile.AID;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVParseException;
import pro.javacard.tlv.TLVs;
import pro.javacard.tlv.Tag;

import java.nio.charset.StandardCharsets;
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

        var entries = CRSCookbook.parse_crs_status(data);
        assertEquals(entries.size(), 2);

        assertEquals(entries.get(0).aid().toString(), "D245007700");
        assertEquals(entries.get(0).lifecycle(), 0x07);
        assertEquals(entries.get(0).clState(), CRSCookbook.CRSEntry.ACTIVATED);

        assertEquals(entries.get(1).aid().toString(), "A000000151");
        assertEquals(entries.get(1).lifecycle(), 0x07);
        assertEquals(entries.get(1).clState(), CRSCookbook.CRSEntry.DEACTIVATED);
    }

    @Test
    public void testParseStatusWithCrel() {
        // One 61 record carrying an A4 CREL list (two 4F AIDs), one without.
        // Built with the TLV library so the lengths are computed, not hand-written.
        var withCrel = TLV.of(Tag.ber(0x61), List.of(
                TLV.of(Tag.ber(0x4F), HexUtils.hex2bin("D245007700")),
                TLV.of(Tag.ber(0x9F, 0x70), HexUtils.hex2bin("0701")),
                TLV.of(Tag.ber(0x80), HexUtils.hex2bin("0009")),
                // Display Control Template carrying a URL sub-tag, to exercise nested verbose rendering
                TLV.of(Tag.ber(0x7F, 0x20), List.of(
                        TLV.of(Tag.ber(0x5F, 0x50), HexUtils.hex2bin("687474703A2F2F78")))),
                TLV.of(Tag.ber(0xA4), List.of(
                        TLV.of(Tag.ber(0x4F), HexUtils.hex2bin("A000000151")),
                        TLV.of(Tag.ber(0x4F), HexUtils.hex2bin("A00000015143525300"))))));
        var plain = TLV.of(Tag.ber(0x61), List.of(
                TLV.of(Tag.ber(0x4F), HexUtils.hex2bin("A000000151")),
                TLV.of(Tag.ber(0x9F, 0x70), HexUtils.hex2bin("0700"))));
        var data = TLVs.of(withCrel, plain).encode();

        var entries = CRSCookbook.parse_crs_status(data);
        assertEquals(entries.size(), 2);
        // The first entry exposes its referenced CREL AIDs, in order
        assertEquals(entries.get(0).aid().toString(), "D245007700");
        assertEquals(entries.get(0).crelList().size(), 2);
        assertEquals(entries.get(0).crelList().get(0).toString(), "A000000151");
        assertEquals(entries.get(0).crelList().get(1).toString(), "A00000015143525300");
        // Absent A4 yields an empty list, not an error
        assertTrue(entries.get(1).crelList().isEmpty());
        // The full registry data is retained, including the nested display template and its URL
        assertEquals(GlobalPlatformCookbook.big_endian(TLV.findAll(entries.get(0).data(), 0x80).get(0).value()), 9);
        var url = TLV.findAll(entries.get(0).data(), 0x7F20).get(0).children().findAll(0x5F50).get(0).value();
        assertEquals(new String(url, StandardCharsets.US_ASCII), "http://x");
    }

    @Test
    public void testParseInfoBare() {
        // A5 { 9F08 version = 0100, 80 counter = 0005 }
        var data = HexUtils.hex2bin("A5099F0802010080020005");
        var info = CRSCookbook.parse_crs_info(data);
        assertEquals(info.version(), 0x0100);
        assertEquals(info.counter(), 5);
    }

    @Test
    public void testParseInfoRejectsFci() {
        // parse_crs_info handles only the bare GET DATA(A5) response (GPC 2.3 Contactless, Table 3-32).
        // A 6F-wrapped SELECT FCI (no top-level A5) is parse_fci's job and must not be accepted here.
        var data = HexUtils.hex2bin("6F1684" + "09A00000015143525300"
                + "A5099F0802010080020005");
        assertThrows(TLVParseException.class, () -> CRSCookbook.parse_crs_info(data));
    }

    @Test
    public void testParseFailuresA1() {
        // A1 failed-list carrying two 4F AIDs
        var data = HexUtils.hex2bin("A10E4F05D2450077004F05A000000151");
        var aids = CRSCookbook.parse_crs_failures(data);
        assertEquals(aids.size(), 2);
        assertEquals(aids.get(0).toString(), "D245007700");
        assertEquals(aids.get(1).toString(), "A000000151");
    }

    @Test
    public void testParseFailures61() {
        // 61 template carrying two 4F AIDs
        var data = HexUtils.hex2bin("610E4F05D2450077004F05A000000151");
        var aids = CRSCookbook.parse_crs_failures(data);
        assertEquals(aids.size(), 2);
        assertEquals(aids.get(0).toString(), "D245007700");
        assertEquals(aids.get(1).toString(), "A000000151");
    }

    // --- Replay tests against real-card captures (resources/crs-*.dump, captured with `gp --ng ... --dump`) ---
    // Each dump is the exact SELECT + command exchange gp sent to a live card; the recipes are
    // cooked in the same order so MockBIBO's command verification confirms the wire bytes too.

    private Chef chef_from_dump(final String resource) {
        final var dump = DumpFormat.parse(getClass().getResourceAsStream(resource));
        return Chef.of(MockBIBO.fromDump(dump));
    }

    // The application toggled across the set-status dumps.
    private static final AID TARGET = AID.fromString("A000000003143117140617005643");

    @Test
    public void testCrsInfoFromDump() {
        final var chef = chef_from_dump("/crs-info.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(CRSCookbook.CRS_AID));
        final var info = chef.cook(CRSCookbook.crs_get_data());
        assertEquals(info.version(), 0x0100);
        assertEquals(info.counter(), 31);
    }

    @Test
    public void testCrsListFromDump() {
        final var chef = chef_from_dump("/crs-list.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(CRSCookbook.CRS_AID));
        // No 5C tag list is sent: the card returns all available data
        final var entries = chef.cook(CRSCookbook.crs_get_status(new byte[0]));
        assertEquals(entries.size(), 6);
        // First entry: the Card Manager / ISD
        assertEquals(entries.get(0).aid().toString(), "A000000151000000");
        assertEquals(entries.get(0).lifecycle(), 0x0F);
        assertEquals(entries.get(0).clState(), CRSCookbook.CRSEntry.ACTIVATED);
        // The CRS itself appears in its own listing
        assertEquals(entries.get(1).aid().toString(), "A00000015143525300");
        // The toggled application, activated in this capture
        assertEquals(entries.get(4).aid().toString(), "A000000003143117140617005643");
        assertEquals(entries.get(4).clState(), CRSCookbook.CRSEntry.ACTIVATED);
        // The full registry data per application is retained: this capture carries 80 counter, 81 priority, 88 display
        assertEquals(GlobalPlatformCookbook.big_endian(TLV.findAll(entries.get(0).data(), 0x80).get(0).value()), 5);
        assertEquals(TLV.findAll(entries.get(0).data(), 0x81).get(0).value()[0], 0x00);
        assertEquals(TLV.findAll(entries.get(0).data(), 0x88).get(0).value()[0], 0x00);
        // This card carries no CREL references (no A4 returned)
        assertTrue(entries.stream().allMatch(e -> e.crelList().isEmpty()));

        // A second card whose listing spans two GET STATUS rounds (6310 continuation) and carries
        // CREL references, an opaque A6 discretionary template and an 87 Application Family.
        final var rich = chef_from_dump("/crs-list-rich.dump");
        rich.cook(GlobalPlatformCookbook.select_aid(CRSCookbook.CRS_AID));
        final var all = rich.cook(CRSCookbook.crs_get_status(new byte[0]));
        assertEquals(all.size(), 8);
        // The PPSE references the payment application as its CREL listener
        assertEquals(all.get(2).aid().toString(), "325041592E5359532E4444463031");
        assertEquals(all.get(2).crelList(), List.of(AID.fromString("D233000000775041592D303101")));
        // The payment application: references the PPSE back, and declares a Financial AFI family (87 = 20)
        assertEquals(all.get(7).aid().toString(), "D233000000775041592D303101");
        assertEquals(all.get(7).crelList(), List.of(AID.fromString("325041592E5359532E4444463031")));
        var afi = TLV.findAll(all.get(7).data(), 0x87).get(0).value()[0] & 0xFF;
        assertEquals(GPRegistryEntryNG.ByteEnum.find(GPRegistryEntryNG.AppFamily.class, afi).orElseThrow(),
                GPRegistryEntryNG.AppFamily.FINANCIAL);
    }

    @Test
    public void testCrsListPrefixFromDump() {
        final var chef = chef_from_dump("/crs-list-prefix.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(CRSCookbook.CRS_AID));
        // A partial-AID search: MockBIBO verifies the 4F05D233000000 wire command, and only the
        // two D233... applications come back.
        final var entries = chef.cook(CRSCookbook.crs_get_status(HexUtils.hex2bin("D233000000")));
        assertEquals(entries.size(), 2);
        assertTrue(entries.stream().allMatch(e -> e.aid().toString().startsWith("D233000000")));
        assertEquals(entries.get(1).crelList(), List.of(AID.fromString("325041592E5359532E4444463031")));
    }

    @Test
    public void testCrsDeactivateFromDump() {
        final var chef = chef_from_dump("/crs-deactivate.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(CRSCookbook.CRS_AID));
        final var failed = chef.cook(CRSCookbook.crs_set_status(List.of(TARGET), false));
        assertTrue(failed.isEmpty());
    }

    @Test
    public void testCrsActivateFromDump() {
        final var chef = chef_from_dump("/crs-activate.dump");
        chef.cook(GlobalPlatformCookbook.select_aid(CRSCookbook.CRS_AID));
        final var failed = chef.cook(CRSCookbook.crs_set_status(List.of(TARGET), true));
        assertTrue(failed.isEmpty());
    }
}
