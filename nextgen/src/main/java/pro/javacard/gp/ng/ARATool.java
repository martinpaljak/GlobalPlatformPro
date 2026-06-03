// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import java.util.ArrayList;
import java.util.List;

import static pro.javacard.gp.ng.GPToolNG.verbose;
import static apdu4j.core.HexUtils.bin2hex;

// Secure Element Access Control (ARA-M) tool-side presentation.
final class ARATool {
    private ARATool() {}

    // SEAC event access rule (SEAC Table 4-1): 00 NEVER, 01 ALWAYS, otherwise an APDU filter
    static String ara_rule_word(byte[] v) {
        if (v.length == 1 && v[0] == 0x00) {
            return "NEVER";
        }
        if (v.length == 1 && v[0] == 0x01) {
            return "ALWAYS";
        }
        return bin2hex(v);
    }

    static void print_ara_list(List<ARACookbook.AccessRule> rules, boolean verbose) {
        if (rules.isEmpty()) {
            verbose("No access rules");
            return;
        }
        var tab = "     ";
        for (var r : rules) {
            var aid = r.aid().filter(a -> a.getBytes().length > 0).map(a -> bin2hex(a.getBytes())).orElse("<all applications>");
            var hash = r.hash().filter(h -> h.length > 0).map(h -> bin2hex(h)).orElse("<any certificate>");
            System.out.println("%s %s".formatted(aid, hash));
            var lines = new ArrayList<String>();
            r.apduRule().ifPresent(v -> lines.add("APDU: " + ara_rule_word(v)));
            r.nfcRule().ifPresent(v -> lines.add("NFC:  " + ara_rule_word(v)));
            if (verbose) {
                // The raw REF-AR-DO structure, for rules the labels above do not fully capture
                for (var t : r.data()) {
                    lines.addAll(t.visualize());
                }
            }
            for (var line : lines) {
                System.out.println(tab + line);
            }
        }
    }
}
