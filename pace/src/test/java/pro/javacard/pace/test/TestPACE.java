// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.pace.test;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.pace.PACE;

import java.math.BigInteger;

public class TestPACE {

    // 379*G on secp256r1 has a 31 byte x coordinate
    @Test
    public void testShortSharedSecret() {
        final var curve = ECNamedCurveTable.getParameterSpec("secp256r1");
        final var secret = PACE.generateSharedSecret(curve, BigInteger.valueOf(379).toByteArray(), curve.getG().getEncoded(false));

        Assert.assertEquals(secret.length, 32);
        Assert.assertEquals(secret[0], 0);
    }
}
