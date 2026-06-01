// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import org.testng.annotations.Test;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TPath;

import static org.testng.Assert.assertEquals;

// Test the A5/82 Communication Interface Access per Instance install parameter (GPC Amendment C, Table 5-1/5-2)
public class TestContactlessInterface {

    // Build install parameters exactly as the command line would
    private static byte[] params(String... argv) {
        return GPToolNG.install_params(GPCommandLineInterface.parser.parse(argv));
    }

    // Build the EF for the given interface mask via the matching --cl-contact/--cl-contactless flags
    private static TLV efOf(int mask) {
        var argv = switch (mask) {
            case 0x80 -> new String[]{"--cl-contact"};
            case 0x40 -> new String[]{"--cl-contactless"};
            default -> new String[]{"--cl-contact", "--cl-contactless"}; // 0xC0 (both/neither)
        };
        return TLV.parse(params(argv)).find(0xEF).orElseThrow();
    }

    // Extract the A5 -> 82 value, asserting A5 is nested under A0
    private static byte[] perInstance(TLV ef) {
        // EF -> A0 -> A5 -> 82
        return TPath.find(ef.children(), 0xA0, 0xA5, 0x82).orElseThrow().value();
    }

    @Test
    public void testDefaultBoth() {
        assertEquals(perInstance(efOf(0xC0)), new byte[]{(byte) 0xC0});
    }

    @Test
    public void testContactOnly() {
        assertEquals(perInstance(efOf(0x80)), new byte[]{(byte) 0x80});
    }

    @Test
    public void testContactlessOnly() {
        assertEquals(perInstance(efOf(0x40)), new byte[]{(byte) 0x40});
    }

    @Test
    public void testBoth() {
        assertEquals(perInstance(efOf(0xC0)), new byte[]{(byte) 0xC0});
    }

    @Test
    public void testActivatedCarriesBoth81AndA5() {
        var ef = TLV.parse(params("--cl-activated", "--cl-contact", "--cl-contactless")).find(0xEF).orElseThrow();
        // A0 carries both the activation state (81) and the A5 interface template
        assertEquals(TPath.find(ef.children(), 0xA0, 0x81).orElseThrow().value(), new byte[]{0x01});
        assertEquals(TPath.find(ef.children(), 0xA0, 0xA5, 0x82).orElseThrow().value(), new byte[]{(byte) 0xC0});
    }

    @Test
    public void testExactEfBytes() {
        // C9 00 (empty app params) + EF { A0 { A5 { 82 01 C0 } } } -> C9 00 EF 07 A0 05 A5 03 82 01 C0
        assertEquals(params("--cl-contact", "--cl-contactless"), new byte[]{
                (byte) 0xC9, 0x00,
                (byte) 0xEF, 0x07,
                (byte) 0xA0, 0x05,
                (byte) 0xA5, 0x03,
                (byte) 0x82, 0x01, (byte) 0xC0});
    }
}
