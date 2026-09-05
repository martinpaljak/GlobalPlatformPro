// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Optional;

// ECC curves that have a Key Parameter Reference assigned in GPC 2.3.1 Table B-2. The constant name
// is the curve name, as known to BouncyCastle.
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

    // The uncompressed encoding of TR-03111 section 3.2.1: '04' and two field-wide coordinates that
    // satisfy the curve equation. Compressed points and the point at infinity are not keys of GPC 2.3.1 B.4.4.
    public ECPublicKey toPublicKey(final byte[] point) throws GeneralSecurityException {
        if (point.length != 1 + 2 * fieldLength() || point[0] != 0x04) {
            throw new IllegalArgumentException("Not an uncompressed point of %s: %s".formatted(name(), HexUtils.bin2hex(point)));
        }
        try {
            final var q = curve.getCurve().decodePoint(point).normalize();
            final var w = new ECPoint(q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger());
            return (ECPublicKey) KeyFactory.getInstance("EC", GPCrypto.BC).generatePublic(new ECPublicKeySpec(w, parameters()));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Point is not on %s: %s".formatted(name(), HexUtils.bin2hex(point)));
        }
    }

    // GPC 2.3.1 B.4.3: r and s are each as long as this
    public int orderLength() {
        return (curve.getN().bitLength() + 7) / 8;
    }

    private int fieldLength() {
        return (curve.getCurve().getFieldSize() + 7) / 8;
    }

    // A key as given on the command line: "curve:hex", or a bare uncompressed point on secp256r1.
    // Empty when the value names no curve and is no point, leaving it to be read as something else.
    public static Optional<KeyPair> keys(final String spec) throws GeneralSecurityException {
        final var colon = spec.indexOf(':');
        if (colon < 0) {
            return point(secp256r1, spec);
        }
        final var named = forName(spec.substring(0, colon));
        if (named.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(keys(named.get(), HexUtils.stringToBin(spec.substring(colon + 1))));
    }

    // Without a curve to name it, only a public point is unmistakable: a private scalar is the size
    // of a symmetric key and a value that is no key at all is not an error here.
    private static Optional<KeyPair> point(final GPCurve curve, final String hex) throws GeneralSecurityException {
        final byte[] value;
        try {
            value = HexUtils.stringToBin(hex);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        return value.length == 1 + 2 * curve.fieldLength() ? Optional.of(new KeyPair(curve.toPublicKey(value), null)) : Optional.empty();
    }

    private static KeyPair keys(final GPCurve curve, final byte[] value) throws GeneralSecurityException {
        if (value.length == 1 + 2 * curve.fieldLength()) {
            return new KeyPair(curve.toPublicKey(value), null);
        }
        if (value.length == curve.orderLength()) {
            final var key = curve.toPrivateKey(value);
            return new KeyPair(curve.toPublicKey(key), key);
        }
        throw new IllegalArgumentException("Not a point or a private key of " + curve.name());
    }

    // A scalar inside the order of the curve, never shown in an error
    private ECPrivateKey toPrivateKey(final byte[] scalar) throws GeneralSecurityException {
        final var d = new BigInteger(1, scalar);
        if (d.signum() == 0 || d.compareTo(curve.getN()) >= 0) {
            throw new IllegalArgumentException("Not a private key of " + name());
        }
        return (ECPrivateKey) KeyFactory.getInstance("EC", GPCrypto.BC).generatePrivate(new ECPrivateKeySpec(d, parameters()));
    }

    private ECPublicKey toPublicKey(final ECPrivateKey key) throws GeneralSecurityException {
        return toPublicKey(curve.getG().multiply(key.getS()).normalize().getEncoded(false));
    }
}
