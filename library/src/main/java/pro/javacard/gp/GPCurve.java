// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Optional;

// ECC curves that have a Key Parameter Reference assigned in GPC 2.3.1 Table B-2. The constant name
// is the curve name, as known to BouncyCastle.
@SuppressWarnings("ImmutableEnumChecker") // X9ECParameters is effectively immutable
public enum GPCurve {
    secp256r1(0x00), // P-256
    secp384r1(0x01), // P-384
    secp521r1(0x02), // P-521
    brainpoolP256r1(0x03),
    brainpoolP256t1(0x04),
    brainpoolP384r1(0x05),
    brainpoolP384t1(0x06),
    brainpoolP512r1(0x07),
    brainpoolP512t1(0x08);

    private final int reference;
    private final X9ECParameters curve;

    GPCurve(final int reference) {
        this.reference = reference;
        this.curve = ECNamedCurveTable.getByName(name());
    }

    public int reference() {
        return reference;
    }

    // Hash to be used with a signature made by a key on this curve, GPC 2.3.1 Table B-3
    public String digest() {
        return GPCrypto.ecdsa_digest(curve.getN().bitLength());
    }

    public ECParameterSpec parameters() {
        return new ECNamedCurveSpec(name(), curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
    }

    // Also matches the aliases of the named curve table, like "P-256" for secp256r1
    public static Optional<GPCurve> forName(final String name) {
        return Optional.ofNullable(ECNamedCurveTable.getByName(name))
                .flatMap(x9 -> forParameters(new ECNamedCurveSpec(name, x9.getCurve(), x9.getG(), x9.getN(), x9.getH())));
    }

    // Empty for the proprietary and local reference ranges, where the curve is up to the card
    public static Optional<GPCurve> forReference(final int reference) {
        return Arrays.stream(values()).filter(c -> c.reference == reference).findFirst();
    }

    public static Optional<GPCurve> forKey(final ECPublicKey key) {
        return forParameters(key.getParams());
    }

    // Matched on the domain parameters: the field size alone does not tell P-256 from brainpoolP256r1
    private static Optional<GPCurve> forParameters(final ECParameterSpec params) {
        return Arrays.stream(values()).filter(c -> {
            final var mine = c.parameters();
            return mine.getCurve().equals(params.getCurve()) && mine.getOrder().equals(params.getOrder())
                    && mine.getGenerator().equals(params.getGenerator());
        }).findFirst();
    }

    // Uncompressed encoding of TR-03111 section 3.2.1, starting with '04'
    public byte[] encodePoint(final ECPublicKey key) {
        final var w = key.getW();
        return curve.getCurve().createPoint(w.getAffineX(), w.getAffineY()).getEncoded(false);
    }

    // Throws if the point is not on this curve
    public ECPublicKey toPublicKey(final byte[] point) throws GeneralSecurityException {
        final var q = curve.getCurve().decodePoint(point).normalize();
        final var w = new ECPoint(q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger());
        return (ECPublicKey) KeyFactory.getInstance("EC", GPCrypto.BC).generatePublic(new ECPublicKeySpec(w, parameters()));
    }
}
