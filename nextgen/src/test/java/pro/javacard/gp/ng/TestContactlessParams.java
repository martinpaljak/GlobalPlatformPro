// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.core.HexUtils;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.tlv.TLVs;
import org.testng.annotations.Test;

import java.util.stream.Stream;

import static org.testng.Assert.*;

// Test the authoritative install parameters builder: the Amendment C contactless EF template
// and the --domain SCP/extradition parameters
public class TestContactlessParams {

    // Build install parameters exactly as the command line would
    private static byte[] params(String... argv) {
        return GPToolNG.install_params(GPCommandLineInterface.parser.parse(argv));
    }

    // Build --domain install parameters as the command line would.
    // --allow-to/--allow-from are only available together with --domain, so it is always present.
    private static byte[] domainParams(GPSecureChannelVersion scp, String... argv) {
        var full = Stream.concat(Stream.of("--domain", "A000000151535041"), Stream.of(argv)).toArray(String[]::new);
        return GPToolNG.domain_install_params(GPCommandLineInterface.parser.parse(full), scp);
    }

    @Test
    public void testEmptyIsC9() {
        // No options at all means empty Application Specific Parameters
        assertEquals(HexUtils.bin2hex(params()), "C900");
    }

    @Test
    public void testActivatedOnly() {
        var result = params("--cl-activated");

        // C9 00 (empty app params) and EF { A0 { 81 01, A5 82 C0 } } with exact length bytes
        assertEquals(HexUtils.bin2hex(result), "C900EF0AA008810101A5038201C0");

        var roots = TLVs.parse(result);
        assertTrue(roots.find(0xC9).isPresent());
        assertEquals(roots.find(0xEF, 0xA0, 0x81).orElseThrow().value(), new byte[]{0x01});
        // A fresh template declares both interfaces by default
        assertEquals(roots.find(0xEF, 0xA0, 0xA5, 0x82).orElseThrow().value(), new byte[]{(byte) 0xC0});
        // No user interaction template when only activation requested
        assertTrue(roots.find(0xEF, 0xA1).isEmpty());
    }

    @Test
    public void testNotifyTwoAids() {
        var a = "A000000151000000";
        var b = "A000000151535041";
        var result = params("--cl-notify", a, "--cl-notify", b);

        var roots = TLVs.parse(result);

        // findAll keeps the full multi-match AID list
        var aids = roots.findAll(0xEF, 0xA1, 0xA3, 0x4F);
        assertEquals(aids.size(), 2);
        assertEquals(aids.get(0).value(), HexUtils.hex2bin(a));
        assertEquals(aids.get(1).value(), HexUtils.hex2bin(b));

        // Interface defaults to both even without an explicit --cl-contact/--cl-contactless
        assertEquals(roots.find(0xEF, 0xA0, 0xA5, 0x82).orElseThrow().value(), new byte[]{(byte) 0xC0});
    }

    @Test
    public void testFamilyAndDisplay() {
        // --cl-family runs through GPUtils.intValue: decimal unless 0x-prefixed
        var result = params("--cl-family", "0x42", "--cl-display-optional");

        var roots = TLVs.parse(result);
        assertEquals(roots.find(0xEF, 0xA1, 0x87).orElseThrow().value(), new byte[]{0x42});
        assertEquals(roots.find(0xEF, 0xA1, 0x88).orElseThrow().value(), new byte[]{0x01});
    }

    @Test
    public void testFullParamsUnchanged() {
        // A complete --params set with no --cl-* option is passed through verbatim
        var base = HexUtils.hex2bin("C9020000");
        assertEquals(params("--params", "C9020000"), base);
    }

    @Test
    public void testExistingEfAmended() {
        // --params already carries EF { A0 { 81 01 } }; --cl-family amends it, CLI added on top
        var result = params("--params", "EF05A003810101", "--cl-family", "07");

        var roots = TLVs.parse(result);
        // Authoritative builder adds the empty C9 sibling
        assertTrue(roots.find(0xC9).isPresent());
        // Existing activation byte is preserved
        assertEquals(roots.find(0xEF, 0xA0, 0x81).orElseThrow().value(), new byte[]{0x01});
        // Missing interface mask defaulted to both, family added
        assertEquals(roots.find(0xEF, 0xA0, 0xA5, 0x82).orElseThrow().value(), new byte[]{(byte) 0xC0});
        assertEquals(roots.find(0xEF, 0xA1, 0x87).orElseThrow().value(), new byte[]{0x07});
    }

    @Test
    public void testRawParamsWrappedWithEfSibling() {
        // Unparseable --params are the C9 application parameters; EF is a top-level sibling, not nested
        var result = params("--params", "0102", "--cl-activated");

        var roots = TLVs.parse(result);
        assertEquals(roots.find(0xC9).orElseThrow().value(), new byte[]{0x01, 0x02});
        assertTrue(roots.find(0xEF, 0xA0, 0x81).isPresent());
        // EF must not be nested inside C9
        assertTrue(roots.find(0xC9, 0xEF).isEmpty());
    }

    @Test
    public void testC9NotFirstPreserved() {
        // A TLV --params where C9 is not the first tag: keep C9 value, append EF as a sibling
        var result = params("--params", "8101AAC90142", "--cl-activated");

        var roots = TLVs.parse(result);
        assertEquals(roots.find(0xC9).orElseThrow().value(), new byte[]{0x42});
        assertEquals(roots.find(0x81).orElseThrow().value(), new byte[]{(byte) 0xAA});
        assertTrue(roots.find(0xEF, 0xA0, 0x81).isPresent());
    }

    @Test
    public void testDomainParams() {
        // Happy path: SCP version (81) plus both extradition rules (82/87) added to a C9-only base
        var roots = TLVs.parse(domainParams(GPSecureChannelVersion.valueOf(0x03, 0x55),
                "--params", "C90100", "--allow-to", "--allow-from"));
        assertEquals(roots.find(0x81).orElseThrow().value(), new byte[]{0x03, 0x55});
        assertEquals(roots.find(0x82).orElseThrow().value(), new byte[]{0x20, 0x20});
        assertEquals(roots.find(0x87).orElseThrow().value(), new byte[]{0x20, 0x20});
        assertTrue(roots.find(0xC9).isPresent());

        // A present tag has the allow-all bits merged in: 0x2020 OR an existing value preserves
        // already-set bits (0xAA already carries 0x20), so AAAA stays AAAA
        assertEquals(domainParams(null, "--params", "8202AAAA", "--allow-to"), HexUtils.hex2bin("8202AAAA"));
        // ... but missing bits are actually merged: 0000 becomes 2020
        assertEquals(TLVs.parse(domainParams(null, "--params", "82020000", "--allow-to"))
                .find(0x82).orElseThrow().value(), new byte[]{0x20, 0x20});

        // Unparseable params pass through without amend, but throw when extradition is requested
        var raw = HexUtils.hex2bin("0102");
        assertEquals(domainParams(null, "--params", "0102"), raw);
        assertThrows(IllegalArgumentException.class, () -> domainParams(null, "--params", "0102", "--allow-to"));
    }
}
