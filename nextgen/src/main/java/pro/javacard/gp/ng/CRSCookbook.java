// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.apdulette.Recipe;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import pro.javacard.capfile.AID;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVParseException;
import pro.javacard.tlv.TLVs;
import pro.javacard.tlv.TPath;
import pro.javacard.tlv.Tag;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import static apdu4j.apdulette.Cookbook.*;
import static pro.javacard.gp.ng.GlobalPlatformCookbook.*;
import static pro.javacard.tlv.TLV.ba;

// Contactless Registry Service (GPC Amendment C) recipes.
// Pure - only data and Recipe composition; the caller's Chef executes them.
public final class CRSCookbook {
    private CRSCookbook() {}

    // Contactless Registry Service application (GPC Amendment C)
    static final byte[] CRS_AID = HexUtils.hex2bin("A00000015143525300");

    // A listed application: AID, lifecycle byte, contactless state byte (9F70),
    // the optional CREL Application AID List (A4) naming its event listeners, and the
    // full set of registry data objects the card returned inside the 61 template (Table 3-9)
    public record CRSEntry(AID aid, int lifecycle, int clState, List<AID> crelList, List<TLV> data) {
        public CRSEntry {
            crelList = List.copyOf(crelList);
            data = List.copyOf(data);
        }

        // Contactless state values (9F70 second byte)
        public static final int DEACTIVATED = 0x00;
        public static final int ACTIVATED = 0x01;
        public static final int NON_ACTIVATABLE = 0x80;
    }

    // CRS version and event counter, from GET DATA (A5) or the SELECT FCI proprietary template
    public record CRSInfo(int version, int counter) {}

    // GET STATUS filter prefix matching all applications
    static final byte[] CRS_ALL = ba(0x4F, 0x00);

    // Parse concatenated 61 templates into listed applications (Amendment C 6.2)
    public static List<CRSEntry> parse_crs_status(final byte[] respData) {
        final var result = new ArrayList<CRSEntry>();
        for (var app : TLV.parse(respData)) {
            if (!app.tag().equals(Tag.ber(0x61))) {
                continue;
            }
            final var aid = new AID(TPath.find(app.children(), 0x4F).orElseThrow().value());
            final var state = TPath.find(app.children(), 0x9F70).orElseThrow().value();
            // 9F70 = [lifecycle, contactless state]
            final var lifecycle = state.length > 0 ? state[0] & 0xFF : 0;
            final var clState = state.length > 1 ? state[1] & 0xFF : 0;
            // A4 is the optional CREL Application AID List: a sequence of 4F AIDs.
            // An application without referenced listeners carries no A4, yielding an empty list.
            final var crelList = TPath.findAll(app.children(), 0xA4, 0x4F).stream()
                    .map(a -> new AID(a.value())).toList();
            result.add(new CRSEntry(aid, lifecycle, clState, crelList, app.children()));
        }
        return result;
    }

    // Parse the bare A5 proprietary template from a GET DATA(A5) response (GPC 2.3 Contactless, Table 3-32)
    public static CRSInfo parse_crs_info(final byte[] respData) {
        final var a5 = TLVs.parse(respData).find(0xA5).orElseThrow(() -> new TLVParseException("No A5 in CRS data"));
        final var ver = TPath.find(a5.children(), 0x9F08).orElseThrow().value();
        final var ctr = TPath.find(a5.children(), 0x80).orElseThrow().value();
        return new CRSInfo(big_endian(ver), big_endian(ctr));
    }

    // Parse failed/conflict AID lists from a SET STATUS error response (A1 or 61 template)
    public static List<AID> parse_crs_failures(final byte[] respData) {
        final var result = new ArrayList<AID>();
        for (var entry : TLV.parse(respData)) {
            final var tag = entry.tag();
            if (tag.equals(Tag.ber(0x4F))) {
                // bare AID at top level
                result.add(new AID(entry.value()));
            } else if (tag.equals(Tag.ber(0xA1)) || tag.equals(Tag.ber(0x61))
                    || tag.equals(Tag.ber(0xA0)) || tag.equals(Tag.ber(0xA2)) || tag.equals(Tag.ber(0xA4))) {
                // list template carrying one or more 4F AIDs
                result.addAll(entry.findAll(0x4F).stream().map(a -> new AID(a.value())).toList());
            }
        }
        return result;
    }

    // CRS GET STATUS (Amendment C 6.2) with 6310 continuation -> listed applications.
    // Empty prefix queries all applications (4F 00). No 5C tag list is sent: omitting it makes
    // the card return all available Contactless Registry Data per application (Amendment C 3.11.3.3.1).
    public static Recipe<List<CRSEntry>> crs_get_status(final byte[] aidPrefix) {
        final var search = aidPrefix == null || aidPrefix.length == 0
                ? CRS_ALL
                : TLV.of(Tag.ber(0x4F), aidPrefix).encode();
        return gather(
                cmd(INS_GET_STATUS, 0x40, 0x00, search),
                0x6310,
                r -> cmd(INS_GET_STATUS, 0x40, 0x01, search),
                0x9000,
                "CRS GET STATUS failed",
                List.of())
                .map(CRSCookbook::parse_crs_status);
    }

    // CRS GET DATA (Amendment C) -> version and event counter
    public static Recipe<CRSInfo> crs_get_data() {
        return data(cmd(INS_GET_DATA, 0x00, 0xA5), CRSCookbook::parse_crs_info);
    }

    // CRS SET STATUS (Amendment C): activate or deactivate one or more applications.
    // P2 = 01 ACTIVATE, 00 DEACTIVATE - never 0x80 (rejected with 6A86).
    // On 6320 (some failed) / 6330 (conflict) the response carries the affected AIDs.
    public static Recipe<List<AID>> crs_set_status(final List<AID> aids, final boolean activate) {
        final var bo = new ByteArrayOutputStream();
        for (var aid : aids) {
            bo.writeBytes(TLV.of(Tag.ber(0x4F), aid.getBytes()).encode());
        }
        return send(cmd(INS_SET_STATUS, 0x01, activate ? 0x01 : 0x00, bo.toByteArray()), any())
                .then(r -> switch (r.getSW()) {
                    case 0x9000 -> Recipe.premade(List.<AID>of());
                    case 0x6320, 0x6330 -> Recipe.premade(parse_crs_failures(r.getData()));
                    default -> Recipe.cardError(r, "CRS SET STATUS failed");
                });
    }
}
