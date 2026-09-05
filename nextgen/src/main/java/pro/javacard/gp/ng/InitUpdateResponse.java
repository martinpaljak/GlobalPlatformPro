// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import pro.javacard.gp.GPDataException;
import pro.javacard.gp.GPUtils;

import java.util.Arrays;

public record InitUpdateResponse(
        byte[] diversificationData,
        int keyVersion,
        int scp,
        Integer scpI,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[] cardCryptogram,
        byte[] sequenceCounter) {
    public InitUpdateResponse {
        diversificationData = diversificationData.clone();
        hostChallenge = hostChallenge.clone();
        cardChallenge = cardChallenge.clone();
        cardCryptogram = cardCryptogram.clone();
        if (sequenceCounter != null) {
            sequenceCounter = sequenceCounter.clone();
        }
    }

    @Override
    public byte[] diversificationData() {
        return diversificationData.clone();
    }

    @Override
    public byte[] hostChallenge() {
        return hostChallenge.clone();
    }

    @Override
    public byte[] cardChallenge() {
        return cardChallenge.clone();
    }

    @Override
    public byte[] cardCryptogram() {
        return cardCryptogram.clone();
    }

    @Override
    public byte[] sequenceCounter() {
        return sequenceCounter == null ? null : sequenceCounter.clone();
    }

    public static InitUpdateResponse parse(byte[] response, byte[] hostChallenge) {
        if (response.length < 28) {
            throw new GPDataException("INIT UPDATE response too short", response);
        }

        var offset = 0;
        final var kdd = Arrays.copyOfRange(response, 0, 10);
        offset += 10;
        final var kvn = response[offset++] & 0xFF;
        final var scpId = response[offset++] & 0xFF;

        Integer scpI = null;
        var counter = false;
        var s16 = false;

        if (scpId == 0x03) {
            scpI = response[offset++] & 0xFF;
            counter = (scpI & 0x10) == 0x10;
            s16 = (scpI & 0x01) == 0x01;
        } else if (scpId != 0x01 && scpId != 0x02) {
            throw new GPDataException("Unrecognized SCP version: " + "0x%02X".formatted(scpId), response);
        }

        byte[] seq = null;
        if (scpId == 0x02) {
            // SCP02: Sequence Counter (2) + Card Challenge (6) + Card Cryptogram (8)
            seq = Arrays.copyOfRange(response, offset, offset + 2);
            offset += 2;
        }

        final var challengeLen = scpId == 0x02 ? 6 : (s16 ? 16 : 8);
        final var cardChallenge = Arrays.copyOfRange(response, offset, offset + challengeLen);
        offset += challengeLen;

        final var cryptogramLen = s16 ? 16 : 8;
        final var cardCryptogram = Arrays.copyOfRange(response, offset, offset + cryptogramLen);
        offset += cryptogramLen;

        if (scpId != 0x02 && counter) {
            seq = Arrays.copyOfRange(response, offset, offset + 3);
        }

        return new InitUpdateResponse(kdd, kvn, scpId, scpI, hostChallenge, cardChallenge, cardCryptogram, seq);
    }

    public boolean s16() {
        return scpI != null && (scpI & 0x01) == 0x01;
    }

    public byte[] sessionContext() {
        if (scp == 0x02) {
            return sequenceCounter.clone();
        }
        return GPUtils.concatenate(hostChallenge, cardChallenge);
    }
}
