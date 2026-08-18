// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.apdulette.Chef;
import apdu4j.core.HexUtils;
import apdu4j.core.MockBIBO;
import org.testng.annotations.Test;
import pro.javacard.capfile.AID;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVs;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.testng.Assert.*;
import static pro.javacard.tlv.TLV.ba;

// Test the SEAC (ARA-M) builders, parser and recipes
public class TestARA {

    private static final AID APPLET = AID.fromString("A0000000030000");
    private static final byte[] HASH = HexUtils.hex2bin("0102030405060708090A0B0C0D0E0F1011121314");

    // A targeted rule (AID + SHA-1 hash, APDU ALWAYS + NFC NEVER) and an all-applets rule
    // (APDU NEVER, NFC ALWAYS), built with the library and round-tripped through the FF40 frame parser.
    @Test
    public void testBuildAndParse() {
        var targeted = new ARACookbook.AccessRule(Optional.of(APPLET), Optional.of(HASH), Optional.of(ba(0x01)), Optional.of(ba(0x00)), List.of());
        var forAll = new ARACookbook.AccessRule(Optional.empty(), Optional.empty(), Optional.of(ba(0x00)), Optional.of(ba(0x01)), List.of());

        var frame = TLV.of(0xFF40, ARACookbook.ref_ar_do(targeted), ARACookbook.ref_ar_do(forAll)).encode();
        var rules = ARACookbook.parse_ara_list(frame);
        assertEquals(rules.size(), 2);

        assertEquals(rules.get(0).aid().orElseThrow().toString(), APPLET.toString());
        assertEquals(rules.get(0).hash().orElseThrow(), HASH);
        assertEquals(rules.get(0).apduRule().orElseThrow(), ba(0x01));
        assertEquals(rules.get(0).nfcRule().orElseThrow(), ba(0x00));
        assertEquals(ARATool.ara_rule_word(rules.get(0).apduRule().orElseThrow()), "ALWAYS");
        assertEquals(ARATool.ara_rule_word(rules.get(0).nfcRule().orElseThrow()), "NEVER");

        assertTrue(rules.get(1).aid().isEmpty());
        assertEquals(rules.get(1).apduRule().orElseThrow(), ba(0x00));
        assertEquals(rules.get(1).nfcRule().orElseThrow(), ba(0x01));
        assertEquals(ARATool.ara_rule_word(rules.get(1).apduRule().orElseThrow()), "NEVER");

        // An empty ARA-M (FF40 with no rules) parses to an empty list
        assertTrue(ARACookbook.parse_ara_list(TLV.of(0xFF40, ba()).encode()).isEmpty());
    }

    // GET DATA [all]/[next] reassembles a frame split across two 9000 responses (length-driven
    // continuation), and the add/delete builders produce the STORE-AR-DO (F0) / DELETE-AR-DO (F1)
    // payloads the caller pumps via STORE DATA.
    @Test
    public void testRecipes() {
        var rule = new ARACookbook.AccessRule(Optional.of(APPLET), Optional.of(HASH), Optional.of(ba(0x01)), Optional.empty(), List.of());
        var frame = TLV.of(0xFF40, ARACookbook.ref_ar_do(rule)).encode();
        var first = Arrays.copyOfRange(frame, 0, frame.length - 5);
        var rest = Arrays.copyOfRange(frame, frame.length - 5, frame.length);

        var chef = Chef.of(MockBIBO.of(HexUtils.bin2hex(first) + "9000", HexUtils.bin2hex(rest) + "9000"));
        var rules = chef.cook(ARACookbook.ara_get_data());
        assertEquals(rules.size(), 1);
        assertEquals(rules.get(0).aid().orElseThrow().toString(), APPLET.toString());

        // add wraps the rule in F0; the F0 round-trips back to the same rule through the list parser
        var added = ARACookbook.store_ar_do(rule);
        assertTrue(TLVs.parse(added).find(0xF0).isPresent());
        var back = ARACookbook.parse_ara_list(TLV.of(0xFF40, TLVs.parse(added).find(0xF0).orElseThrow().children().get(0)).encode());
        assertEquals(back.get(0).aid().orElseThrow().toString(), APPLET.toString());

        // delete builds F1 in all three forms (by rule, by AID, all)
        assertTrue(TLVs.parse(ARACookbook.delete_ar_do(Optional.of(APPLET), Optional.of(HASH))).find(0xF1).isPresent());
        assertTrue(TLVs.parse(ARACookbook.delete_ar_do(Optional.of(APPLET), Optional.empty())).find(0xF1).isPresent());
        assertEquals(TLVs.parse(ARACookbook.delete_ar_do(Optional.empty(), Optional.empty())).find(0xF1).orElseThrow().value().length, 0);

        // a SHA-256 (32-byte) hash is accepted; any other length is rejected on both add and delete
        var sha256 = new ARACookbook.AccessRule(Optional.of(APPLET), Optional.of(new byte[32]), Optional.of(ba(0x01)), Optional.empty(), List.of());
        assertTrue(TLVs.parse(ARACookbook.store_ar_do(sha256)).find(0xF0).isPresent());
        var badHash = new ARACookbook.AccessRule(Optional.of(APPLET), Optional.of(ba(0x01, 0x02, 0x03)), Optional.of(ba(0x01)), Optional.empty(), List.of());
        assertThrows(IllegalArgumentException.class, () -> ARACookbook.store_ar_do(badHash));
        assertThrows(IllegalArgumentException.class, () -> ARACookbook.delete_ar_do(Optional.of(APPLET), Optional.of(ba(0x00))));

        // a card with no rules answers 6A88 to GET DATA [all] - the list comes back empty, not an error
        assertTrue(Chef.of(MockBIBO.of("6A88")).cook(ARACookbook.ara_get_data()).isEmpty());
    }
}
