// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import pro.javacard.capfile.AID;
import pro.javacard.capfile.WellKnownAID;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPUtils;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static pro.javacard.gp.ng.GPToolNG.verbose;
import static apdu4j.core.HexUtils.bin2hex;

// Contactless Registry Service (GPC Amendment C) tool-side presentation.
final class CRSTool {
    private CRSTool() {}

    // Describe a contactless state byte (9F70 second byte)
    static String crs_state_word(int clState) {
        return switch (clState) {
            case CRSCookbook.CRSEntry.ACTIVATED -> "ACTIVATED";
            case CRSCookbook.CRSEntry.DEACTIVATED -> "DEACTIVATED";
            case CRSCookbook.CRSEntry.NON_ACTIVATABLE -> "NON_ACTIVATABLE";
            default -> "0x%02X".formatted(clState);
        };
    }

    // Application lifecycle byte (9F70 first byte) rendered like the registry listing, hex if unrecognized
    private static String crs_lifecycle_word(int lifecycle) {
        return GPRegistryEntryNG.ByteEnum.find(GPRegistryEntryNG.APPLifeCycle.class, lifecycle)
                .map(Enum::name)
                .orElse("0x%02X".formatted(lifecycle));
    }

    static void print_crs_status(List<CRSCookbook.CRSEntry> entries, boolean verbose) {
        if (entries.isEmpty()) {
            verbose("No contactless applications");
            return;
        }
        var tab = "     ";
        for (var e : entries) {
            // Verbose appends the well-known or readable AID name, as in the registry listing
            var name = verbose ? " (" + WellKnownAID.getName(e.aid()).orElse(GPUtils.bin2readable(e.aid().getBytes())) + ")" : "";
            System.out.println("%s %s (%s)%s".formatted(bin2hex(e.aid().getBytes()), crs_state_word(e.clState()), crs_lifecycle_word(e.lifecycle()), name));
            if (!verbose) {
                continue;
            }
            // Every registry data object the card returned for this application, labeled where known
            var lines = new ArrayList<String>();
            for (var t : e.data()) {
                crs_detail(t, lines);
            }
            for (var line : lines) {
                System.out.println(tab + line);
            }
        }
    }

    // A "Label: value" detail line padded to align values, matching the registry listing style.
    // A longer label keeps a single separating space rather than aligning, so nothing collides.
    private static String crs_line(String label, String value) {
        return "%-11s %s".formatted(label + ":", value);
    }

    // An AID-list registry data object (CREL, group, policy): one labeled line per AID, like the registry "Applet:" listing
    private static void crs_aid_list(String label, TLV t, List<String> out) {
        for (var a : t.findAll(0x4F)) {
            out.add(crs_line(label, bin2hex(a.value())));
        }
    }

    // Application Family (87) is an ISO 14443-3 AFI: name the sector when known, always show the byte
    private static String crs_family(byte[] v) {
        if (v.length == 0) {
            return "";
        }
        var afi = v[0] & 0xFF;
        return GPRegistryEntryNG.ByteEnum.find(GPRegistryEntryNG.AppFamily.class, afi)
                .map(f -> "%s (0x%02X)".formatted(f.name(), afi))
                .orElse("0x%02X".formatted(afi));
    }

    // Render one CRS registry data object (Amendment C Table 3-9) as a labeled line, recursing into
    // the Display Control Template. AID and lifecycle/state are skipped: they already head the entry.
    private static void crs_detail(TLV t, List<String> out) {
        var tag = t.tag();
        if (tag.equals(Tag.ber(0x4F)) || tag.equals(Tag.ber(0x9F, 0x70))) {
            return;
        }
        if (tag.equals(Tag.ber(0x7F, 0x20))) {
            // Display Control Template: unfold its display data objects (URL, message, image, ...)
            for (var c : t.children()) {
                crs_detail(c, out);
            }
            return;
        }
        if (tag.equals(Tag.ber(0xA4))) {
            crs_aid_list("CREL", t, out);
        } else if (tag.equals(Tag.ber(0xA2))) {
            crs_aid_list("Head", t, out);
        } else if (tag.equals(Tag.ber(0xA3))) {
            crs_aid_list("Members", t, out);
        } else if (tag.equals(Tag.ber(0xA5))) {
            crs_aid_list("Policy", t, out);
        } else {
            var v = t.value();
            if (tag.equals(Tag.ber(0x80))) {
                out.add(crs_line("Counter", Integer.toString(GlobalPlatformCookbook.big_endian(v))));
            } else if (tag.equals(Tag.ber(0x81))) {
                out.add(crs_line("Priority", Integer.toString(v.length > 0 ? v[0] & 0xFF : 0)));
            } else if (tag.equals(Tag.ber(0x88))) {
                // Display Required Indicator (Amendment C 3.6): 00 (or absent) requires a display, 01 does not
                out.add(crs_line("Display", v.length > 0 && v[0] != 0 ? "not required" : "required"));
            } else if (tag.equals(Tag.ber(0x87))) {
                out.add(crs_line("Family", crs_family(v)));
            } else if (tag.equals(Tag.ber(0x5F, 0x50))) {
                out.add(crs_line("URL", new String(v, StandardCharsets.US_ASCII)));
            } else if (tag.equals(Tag.ber(0x5F, 0x45))) {
                out.add(crs_line("Message", new String(v, StandardCharsets.US_ASCII)));
            } else if (tag.equals(Tag.ber(0x6D))) {
                out.add(crs_line("Image", v.length + " bytes"));
            } else if (tag.equals(Tag.ber(0x89))) {
                out.add(crs_line("Protocols", bin2hex(v)));
            } else if (tag.equals(Tag.ber(0x8A))) {
                // Continuous Processing (Amendment C 6.4): per application, 02 enabled, 01 (or absent) disabled
                out.add(crs_line("Continuous", v.length > 0 && v[0] == 0x02 ? "enabled" : "disabled"));
            } else if (tag.equals(Tag.ber(0x95))) {
                out.add(crs_line("Interfaces", bin2hex(v)));
            } else if (tag.equals(Tag.ber(0x96))) {
                out.add(crs_line("Privacy", v.length > 0 && v[0] != 0 ? "sensitive" : "normal"));
            } else if (tag.equals(Tag.ber(0xA6))) {
                out.add(crs_line("Data", bin2hex(v)));
            } else {
                // Not-yet-labeled registry data: show verbatim so nothing is hidden
                out.add(crs_line(tag.toString(), bin2hex(v)));
            }
        }
    }

    static void print_crs_info(CRSCookbook.CRSInfo info) {
        // Version is the two-byte 9F08 value, shown as major.minor
        System.out.printf("CRS version: %d.%d%n", (info.version() >> 8) & 0xFF, info.version() & 0xFF);
        System.out.println("Update counter: " + info.counter());
    }

    // Silent by default. Verbose reports each AID that actually changed state; a conflict is an error.
    static void crs_set_result(List<AID> requested, boolean activate, List<AID> affected) {
        var word = activate ? "ACTIVATED" : "DEACTIVATED";
        for (var aid : requested) {
            if (!affected.contains(aid)) {
                verbose(bin2hex(aid.getBytes()) + " -> " + word);
            }
        }
        if (!affected.isEmpty()) {
            throw new GPException("SET STATUS conflict for: " + affected.stream().map(a -> bin2hex(a.getBytes())).collect(Collectors.joining(", ")));
        }
    }
}
