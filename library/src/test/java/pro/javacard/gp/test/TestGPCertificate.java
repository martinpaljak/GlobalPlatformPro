// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.test;

import apdu4j.core.HexUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.GPCertificate;
import pro.javacard.gp.GPCurve;
import pro.javacard.gp.GPDataException;
import pro.javacard.gp.GPUtils;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDate;
import java.util.List;

public class TestGPCertificate {

    // Key agreement certificate on secp256r1, made with the builder below and pinned here
    private static final String CERTIFICATE = "7F2181B99304010203044208A0000001510000005F2008A000000151535041950200805F250420"
            + "2601015F2404203612317F4946B04104951CEEA4AA1DAFEEE5CB52527C8362BF8639BAFB34DDF9D02FE242DC8D53AFB86EB977F0075"
            + "3A58A2592466EF5DFAD091BA4689D5FD6735CD6884FC39DBB7FEDF001005F3740392E53D1FC0715DE9769BF7D758A3188DAF80459D5"
            + "342246751394E7E67A0B8D1511A0BA96AF384E96E23FDC93B538F9E3B3B6F021100A4CE141EDD467A949B6";

    // PK.CA.ECDSA of the certificate above
    private static final String CA_POINT = "047E0D5C818E2B34C61247E0C58F27411C0BA782DC395B818FC5AE1F1BD9382D4BDB4CB2D4339765"
            + "0436F9C2D63668F3550877B7968370F321B07639E408AAA48D";

    private static KeyPair keypair(final String curve) throws Exception {
        final var kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    @Test
    public void testKnownCertificate() throws Exception {
        final var bytes = HexUtils.hex2bin(CERTIFICATE);
        final var cert = GPCertificate.parse(bytes);
        System.out.println(cert);

        Assert.assertEquals(HexUtils.bin2hex(cert.serial()), "01020304");
        Assert.assertEquals(HexUtils.bin2hex(cert.ca()), "A000000151000000");
        Assert.assertEquals(HexUtils.bin2hex(cert.subject()), "A000000151535041");
        Assert.assertEquals(cert.usage(), GPCertificate.Usage.AGREEMENT);
        Assert.assertEquals(cert.effective().orElseThrow(), LocalDate.of(2026, 1, 1));
        Assert.assertEquals(cert.expires(), LocalDate.of(2036, 12, 31));
        Assert.assertEquals(cert.curveReference(), GPCurve.secp256r1.reference());
        Assert.assertEquals(cert.signature().length, 64);
        Assert.assertTrue(cert.imageNumber().isEmpty());
        Assert.assertTrue(cert.discretionary().isEmpty());
        Assert.assertTrue(cert.authorizations().isEmpty());
        Assert.assertEquals(GPCurve.forKey(cert.publicKey()).orElseThrow(), GPCurve.secp256r1);
        // Every field in the order it was encoded, tags this class does not model included
        Assert.assertEquals(cert.fields().stream().map(f -> f.tag().toHex()).toList(),
                List.of("[93]", "[42]", "[5F20]", "[95]", "[5F25]", "[5F24]", "[7F49]", "[5F37]"));

        // Parsing keeps the bytes as they arrived
        Assert.assertEquals(HexUtils.bin2hex(cert.encode()), CERTIFICATE);
        Assert.assertTrue(cert.verify(GPCurve.secp256r1.toPublicKey(HexUtils.hex2bin(CA_POINT))));
        // The signature covers the body up to tag '5F37': all but the 4 byte header and the 67 byte signature TLV
        Assert.assertEquals(HexUtils.bin2hex(cert.signedData()), CERTIFICATE.substring(8, CERTIFICATE.length() - 134));
        // Proprietary key parameter references name no curve
        Assert.assertTrue(GPCurve.forReference(0x40).isEmpty());
        // GPC 2.3.1 11.1.9: an absent second byte is assumed to be '00', so '82 00' is '82'
        Assert.assertEquals(minimal("95028200", "5F240420361231", "7F4906B00104F00100").usage(),
                GPCertificate.Usage.VERIFICATION);
    }

    @Test
    public void testBuildSignVerify() throws Exception {
        // GPC 2.3.1 Table B-3: the hash follows the order of the signing key, so a P-521 CA over a
        // P-384 subject signs with SHA-512
        final var ca = keypair("secp521r1");
        final var subject = keypair("secp384r1");

        final var builder = GPCertificate.builder()
                .publicKey((ECPublicKey) subject.getPublic())
                .expires(LocalDate.of(2030, 6, 1))
                .effective(LocalDate.of(2026, 6, 1))
                .usage(GPCertificate.Usage.VERIFICATION)
                .subject(HexUtils.hex2bin("A000000151535041"))
                .ca(HexUtils.hex2bin("A000000151000000"))
                .serial(HexUtils.hex2bin("2A"))
                .imageNumber(HexUtils.hex2bin("0102"))
                .discretionaryTLV(HexUtils.hex2bin("C1020304"))
                .authorizations(HexUtils.hex2bin("E3079005A000000151"))
                .field(0xDD, HexUtils.hex2bin("CAFE"));

        final var cert = builder.sign(ca.getPrivate());
        System.out.println(HexUtils.bin2hex(cert.encode()));

        // The builder signs exactly what the parser reads back as signed
        Assert.assertEquals(cert.signedData(), builder.dtbs());
        // The same certificate, from a signature made elsewhere over those bytes
        Assert.assertEquals(GPCertificate.of(cert.signedData(), cert.signature()), cert);
        Assert.assertTrue(cert.verify((ECPublicKey) ca.getPublic()));
        Assert.assertEquals(cert.signature().length, 132);
        Assert.assertEquals(GPCertificate.parse(cert.encode()), cert);
        Assert.assertEquals(GPCertificate.parse(cert.encode()).hashCode(), cert.hashCode());

        Assert.assertEquals(cert.publicKey().getW(), ((ECPublicKey) subject.getPublic()).getW());
        Assert.assertEquals(cert.curveReference(), GPCurve.secp384r1.reference());
        Assert.assertEquals(cert.effective().orElseThrow(), LocalDate.of(2026, 6, 1));
        Assert.assertEquals(HexUtils.bin2hex(cert.imageNumber().orElseThrow()), "0102");
        Assert.assertEquals(HexUtils.bin2hex(cert.discretionary().orElseThrow()), "C1020304");
        Assert.assertEquals(HexUtils.bin2hex(cert.field(0xDD).orElseThrow()), "CAFE");

        // Setter order does not matter, the fields are emitted in the order of the tables
        final var hex = HexUtils.bin2hex(cert.encode());
        Assert.assertTrue(hex.indexOf("9301") < hex.indexOf("7F49"));
        Assert.assertTrue(hex.indexOf("7F49") < hex.indexOf("DD02"));

        final var tampered = cert.encode();
        tampered[tampered.length - 1] ^= 0x01;
        Assert.assertFalse(GPCertificate.parse(tampered).verify((ECPublicKey) ca.getPublic()));
        // A signature of the wrong length for the curve is not a signature
        Assert.assertFalse(builder.signature(new byte[64]).verify((ECPublicKey) ca.getPublic()));

        // A chain as sent to the card, each certificate verified with the key of the one before it
        final var leaf = GPCertificate.builder()
                .serial(HexUtils.hex2bin("2B"))
                .ca(HexUtils.hex2bin("A000000151535041"))
                .subject(HexUtils.hex2bin("A00000015153504101"))
                .usage(GPCertificate.Usage.AGREEMENT)
                .expires(LocalDate.of(2030, 6, 1))
                .publicKey((ECPublicKey) keypair("secp256r1").getPublic())
                .sign(subject.getPrivate());
        final var chain = GPCertificate.parseChain(GPUtils.concatenate(cert.encode(), leaf.encode()));
        Assert.assertEquals(chain.size(), 2);
        Assert.assertTrue(chain.get(0).verify((ECPublicKey) ca.getPublic()));
        Assert.assertTrue(chain.get(1).verify(chain.get(0).publicKey()));
        // The P-384 subject key signed the leaf, so SHA-384 and 48 byte components
        Assert.assertEquals(leaf.signature().length, 96);

        // GPC 2.3.1 Table B-3
        Assert.assertEquals(GPCurve.secp256r1.digest(), "SHA-256");
        Assert.assertEquals(GPCurve.secp384r1.digest(), "SHA-384");
        Assert.assertEquals(GPCurve.secp521r1.digest(), "SHA-512");
        Assert.assertEquals(GPCurve.brainpoolP512r1.digest(), "SHA-512");
        // Curves are also named by their aliases
        Assert.assertEquals(GPCurve.forName("P-256").orElseThrow(), GPCurve.secp256r1);
        Assert.assertEquals(GPCurve.forName("prime256v1").orElseThrow(), GPCurve.secp256r1);
        Assert.assertEquals(GPCurve.forName("brainpoolP256t1").orElseThrow(), GPCurve.brainpoolP256t1);
        // Not a curve of Table B-2
        Assert.assertTrue(GPCurve.forName("secp192r1").isEmpty());
        Assert.assertTrue(GPCurve.forName("nonsense").isEmpty());
    }

    // A certificate with the mandatory fields, of which the key usage, expiration and public key are given
    private static GPCertificate minimal(final String usage, final String expires, final String publicKey) {
        final var body = "930101" + "420102" + "5F200103" + usage + expires + publicKey + "5F370104";
        return GPCertificate.parse(HexUtils.hex2bin("7F21%02X%s".formatted(body.length() / 2, body)));
    }

    @Test
    public void testRejects() throws Exception {
        final var usage = "950182";
        final var expires = "5F240420361231";
        final var publicKey = "7F4906B00104F00100";

        for (final var bad : List.of(
                "7F4903B00100", // not a certificate
                "7F2105930101", // truncated certificate
                "7F2103930501", // a field reaching past the end
                "7F210E9301014201025F2001035F370104", // mandatory fields missing
                "7F210E9301014201025F3701045F200103", // a field after the signature
                "7F210A9301014201025F200103", // no signature
                "7F2106930101930102", // the same field twice
                CERTIFICATE + "00")) { // more than one certificate
            Assert.assertThrows(GPDataException.class, () -> GPCertificate.parse(HexUtils.hex2bin(bad)));
        }

        // Fields are decoded on access
        Assert.assertThrows(GPDataException.class, () -> minimal("950101", expires, publicKey).usage());
        Assert.assertThrows(GPDataException.class, () -> minimal("9503000080", expires, publicKey).usage());
        // '80' as the first byte is Verification/Encipherment (Table 11-17), not the Key Agreement of Table 11-18
        Assert.assertThrows(GPDataException.class, () -> minimal("950180", expires, publicKey).usage());
        Assert.assertThrows(GPDataException.class, () -> minimal("95020082", expires, publicKey).usage());
        Assert.assertThrows(GPDataException.class, () -> minimal(usage, "5F240420361299", publicKey).expires());
        Assert.assertThrows(GPDataException.class, () -> minimal(usage, "5F2403203612", publicKey).expires());
        Assert.assertThrows(GPDataException.class, () -> minimal(usage, expires, "7F4902B000").curveReference());
        Assert.assertThrows(GPDataException.class, () -> minimal(usage, expires, "7F4905F003000000").curveReference());
        // A proprietary key parameter reference names no curve
        Assert.assertThrows(GPDataException.class, () -> minimal(usage, expires, "7F4906B00104F00140").publicKey());

        // Both '53' and '73' discretionary data
        final var both = GPCertificate.builder().serial(HexUtils.hex2bin("01")).ca(HexUtils.hex2bin("02"))
                .subject(HexUtils.hex2bin("03")).usage(GPCertificate.Usage.VERIFICATION).expires(LocalDate.of(2036, 12, 31))
                .publicKey(HexUtils.hex2bin("04"), 0x00).discretionary(HexUtils.hex2bin("AA")).discretionaryTLV(HexUtils.hex2bin("C10101"));
        Assert.assertThrows(GPDataException.class, () -> both.signature(new byte[64]));

        // Incomplete certificate
        Assert.assertThrows(IllegalStateException.class, () -> GPCertificate.builder().serial(HexUtils.hex2bin("01")).dtbs());
        // A detached signature over something that is not a certificate body
        Assert.assertThrows(GPDataException.class, () -> GPCertificate.of(HexUtils.hex2bin("930101"), new byte[64]));
        // The signature is not a field to be set
        Assert.assertThrows(IllegalArgumentException.class, () -> GPCertificate.builder().field(0x5F37, HexUtils.hex2bin("01")));
        // Not a curve of Table B-2
        Assert.assertThrows(IllegalArgumentException.class, () -> GPCertificate.builder().publicKey((ECPublicKey) keypair("brainpoolP160r1").getPublic()));
        // Not an EC key
        final var rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        Assert.assertThrows(InvalidKeyException.class, () -> both.sign(rsa.generateKeyPair().getPrivate()));
    }
}
