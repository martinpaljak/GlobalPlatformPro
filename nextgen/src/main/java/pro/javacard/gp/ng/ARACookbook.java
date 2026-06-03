// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2017 Bertrand Martel <bmartel.fr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.apdulette.Recipe;
import apdu4j.core.HexUtils;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPUtils;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVParseException;
import pro.javacard.tlv.TLVs;
import pro.javacard.tlv.TPath;
import pro.javacard.tlv.Tag;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static apdu4j.apdulette.Cookbook.*;
import static pro.javacard.gp.ng.GlobalPlatformCookbook.*;
import static pro.javacard.tlv.TLV.ba;

// Secure Element Access Control (GPC SEAC v1.1) recipes against an ARA-M / ARA-C applet.
// Pure - only data and Recipe composition; the caller's Chef executes them.
// Thanks to Bertrand Martel for the initial SEAC / access-control implementation.
public final class ARACookbook {
    private ARACookbook() {}

    // The well-known Access Rule Application Master (ARA-M)
    static final byte[] ARA_AID = HexUtils.hex2bin("A00000015141434C00");

    // SEAC data objects (SEAC Table 6-1): the GET DATA [all] response wraps the REF-AR-DO list
    private static final int RESPONSE_ALL_AR = 0xFF40;
    private static final int REF_AR_DO = 0xE2;
    private static final int REF_DO = 0xE1;
    private static final int AID_REF_DO = 0x4F;
    private static final int HASH_REF_DO = 0xC1;
    private static final int AR_DO = 0xE3;
    private static final int APDU_AR_DO = 0xD0;
    private static final int NFC_AR_DO = 0xD1;
    private static final int STORE_AR_DO = 0xF0;
    private static final int DELETE_AR_DO = 0xF1;

    // One access rule: a (target applet AID, certificate hash) reference bound to APDU and NFC rules,
    // plus the raw REF-AR-DO children the card returned. AID and hash may be absent (a rule for all).
    public record AccessRule(Optional<AID> aid, Optional<byte[]> hash, Optional<byte[]> apduRule,
                             Optional<byte[]> nfcRule, List<TLV> data) {
        public AccessRule {
            data = List.copyOf(data);
        }
    }

    // Decode the FF40 GET DATA [all] frame into access rules (SEAC 4.2.2)
    public static List<AccessRule> parse_ara_list(final byte[] frame) {
        final var result = new ArrayList<AccessRule>();
        final var framed = TLVs.parse(frame).find(RESPONSE_ALL_AR);
        if (framed.isEmpty()) {
            return result;
        }
        for (final var ref : framed.get().children()) {
            if (!ref.tag().equals(Tag.ber(REF_AR_DO))) {
                continue;
            }
            final var aid = TPath.find(ref.children(), REF_DO, AID_REF_DO).map(t -> new AID(t.value()));
            final var hash = TPath.find(ref.children(), REF_DO, HASH_REF_DO).map(TLV::value);
            final var apdu = TPath.find(ref.children(), AR_DO, APDU_AR_DO).map(TLV::value);
            final var nfc = TPath.find(ref.children(), AR_DO, NFC_AR_DO).map(TLV::value);
            result.add(new AccessRule(aid, hash, apdu, nfc, ref.children()));
        }
        return result;
    }

    // GET DATA [all] (FF40), then [next] (FF60) until the FF40 frame is complete (SEAC 4.2.2).
    // Every exchange returns 9000; completion is length-driven, signalled by the frame parsing whole.
    public static Recipe<List<AccessRule>> ara_get_data() {
        return ara_collect(new byte[0], true).map(ARACookbook::parse_ara_list);
    }

    private static Recipe<byte[]> ara_collect(final byte[] acc, final boolean first) {
        return send(cmd(INS_GET_DATA, 0xFF, first ? 0x40 : 0x60), first ? expect(0x9000, 0x6A88) : expect(0x9000)).then(r -> {
            // A card with no access rules may answer 6A88 instead of an empty FF40 frame
            if (r.getSW() == 0x6A88) {
                return Recipe.premade(TLV.of(RESPONSE_ALL_AR, ba()).encode());
            }
            final var raw = GPUtils.concatenate(acc, r.getData());
            return complete_frame(raw) ? Recipe.premade(raw) : ara_collect(raw, false);
        });
    }

    // True once the accumulated bytes form a complete FF40 BER frame
    private static boolean complete_frame(final byte[] raw) {
        try {
            return TLVs.parse(raw).find(RESPONSE_ALL_AR).isPresent();
        } catch (TLVParseException incomplete) {
            return false;
        }
    }

    // STORE-AR-DO (F0) carrying one REF-AR-DO, the STORE DATA payload that adds a rule (SEAC 4.2.1).
    // The caller personalizes the ARA applet and pumps this over the secure channel.
    public static byte[] store_ar_do(final AccessRule rule) {
        return TLV.of(STORE_AR_DO, ref_ar_do(rule)).encode();
    }

    // DeviceAppID-REF-DO (C1) carries a certificate hash: SHA-256 (32) or the deprecated SHA-1 (20) (SEAC Table 6-4)
    static byte[] check_hash(final byte[] hash) {
        if (hash.length != 32 && hash.length != 20) {
            throw new IllegalArgumentException("Certificate hash must be 32 (SHA-256) or 20 (SHA-1) bytes, got " + hash.length);
        }
        return hash;
    }

    static TLV ref_ar_do(final AccessRule rule) {
        final var refDo = new ArrayList<TLV>();
        rule.aid().ifPresent(a -> refDo.add(TLV.of(AID_REF_DO, a.getBytes())));
        rule.hash().ifPresent(h -> refDo.add(TLV.of(HASH_REF_DO, check_hash(h))));
        final var arDo = new ArrayList<TLV>();
        rule.apduRule().ifPresent(v -> arDo.add(TLV.of(APDU_AR_DO, v)));
        rule.nfcRule().ifPresent(v -> arDo.add(TLV.of(NFC_AR_DO, v)));
        return TLV.of(REF_AR_DO, TLV.of(Tag.ber(REF_DO), refDo), TLV.of(Tag.ber(AR_DO), arDo));
    }

    // DELETE-AR-DO (F1), the STORE DATA payload that deletes rules (SEAC 4.2.1): empty deletes all
    // rules, an AID deletes that applet's rules, an AID+hash deletes that specific rule.
    public static byte[] delete_ar_do(final Optional<AID> aid, final Optional<byte[]> hash) {
        if (aid.isPresent() && hash.isPresent()) {
            final var refDo = TLV.of(REF_DO, TLV.of(AID_REF_DO, aid.get().getBytes()), TLV.of(HASH_REF_DO, check_hash(hash.get())));
            return TLV.of(DELETE_AR_DO, TLV.of(REF_AR_DO, refDo)).encode();
        } else if (aid.isPresent()) {
            return TLV.of(DELETE_AR_DO, TLV.of(AID_REF_DO, aid.get().getBytes())).encode();
        } else {
            return TLV.of(DELETE_AR_DO, ba()).encode();
        }
    }
}
