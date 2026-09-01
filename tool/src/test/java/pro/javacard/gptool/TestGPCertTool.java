// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gptool;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.GPCertificate;
import pro.javacard.gp.GPCurve;
import pro.javacard.gp.GPDataException;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.LocalDate;

public class TestGPCertTool {

    static final String CA = "../library/src/test/resources/test-dap-p256-priv.pem";
    static final String CA_PUBLIC = "../library/src/test/resources/test-dap-p256-pub.pem";

    static int gp(final String... argv) throws Exception {
        return GPCertTool.run(GPCommandLineInterface.parser.parse(argv));
    }

    static Path temp() throws Exception {
        final var file = Files.createTempFile("gptest", ".cert");
        file.toFile().deleteOnExit();
        return file;
    }

    @Test
    public void testConstructAndVerify() throws Exception {
        final var file = temp();
        Assert.assertEquals(gp("--cert-new", "--cert-serial", "01", "--cert-ca", "|Kloc CA|", "--cert-subject", "A0:00:00:01:51:53:50",
                "--cert-usage", "agreement", "--cert-effective", "2026-01-01", "--cert-expires", "2036-12-31", "--cert-pubkey", CA_PUBLIC, "--cert-sign", CA,
                "--cert-out", file.toString()), 0);

        // |text| is literal text, anything else that reads as hex decodes to bytes
        final var certificate = GPCertificate.parse(Files.readAllBytes(file));
        Assert.assertEquals(certificate.ca(), "Kloc CA".getBytes(StandardCharsets.US_ASCII));
        Assert.assertEquals(certificate.subject(), HexUtils.hex2bin("A0000001515350"));
        Assert.assertEquals(certificate.serial(), HexUtils.hex2bin("01"));
        Assert.assertEquals(certificate.usage(), GPCertificate.Usage.AGREEMENT);
        Assert.assertEquals(certificate.expires(), LocalDate.of(2036, 12, 31));
        Assert.assertEquals(certificate.effective().orElseThrow(), LocalDate.of(2026, 1, 1));
        Assert.assertEquals(certificate.curveReference(), GPCurve.secp256r1.reference());

        Assert.assertEquals(certificate.toString(), "GP certificate 01 for A0000001515350 by Kloc CA, expires 2036-12-31");

        Assert.assertEquals(gp("--cert-in", file.toString()), 0);
        Assert.assertEquals(gp("--cert-in", file.toString(), "--cert-verify", CA_PUBLIC), 0);
        // The certificate is self-signed: its own issuer
        Assert.assertEquals(gp("--cert-in", file.toString(), "--cert-verify", file.toString()), 0);
        // Changing a field invalidates the signature already in the file
        Assert.assertEquals(gp("--cert-in", file.toString(), "--cert-serial", "09", "--cert-sign", CA, "--cert-out", file.toString()), 0);
        Assert.assertEquals(GPCertificate.parse(Files.readAllBytes(file)).serial(), HexUtils.hex2bin("09"));
        Assert.assertEquals(gp("--cert-in", file.toString(), "--cert-verify", CA_PUBLIC), 0);

        // The same CA key as a scalar on the command line: it derives the same public key and signs the same way
        final var scalar = "secp256r1:%064x".formatted(((ECPrivateKey) Key.valueOf(CA).getPrivate().orElseThrow()).getS());
        final var software = temp();
        Assert.assertEquals(gp("--cert-new", "--cert-serial", "02", "--cert-ca", "|Kloc CA|", "--cert-subject", "|OCE|", "--cert-usage",
                "verification", "--cert-expires", "2036-12-31", "--cert-pubkey", scalar, "--cert-sign", scalar,
                "--cert-out", software.toString()), 0);
        Assert.assertEquals(GPCertificate.parse(Files.readAllBytes(software)).publicKey(),
                Key.valueOf(CA_PUBLIC).getPublic().orElseThrow());
        Assert.assertEquals(gp("--cert-in", software.toString(), "--cert-verify", CA_PUBLIC), 0);

        // A signature made elsewhere attaches to an unchanged certificate as well
        final var attached = temp();
        Assert.assertEquals(gp("--cert-in", file.toString(), "--cert-signature",
                HexUtils.bin2hex(GPCertificate.parse(Files.readAllBytes(file)).signature()), "--cert-out", attached.toString()), 0);
        Assert.assertEquals(Files.readAllBytes(attached), Files.readAllBytes(file));

        // Hex on the way in as well, and a bare public key point as the issuer
        final var hex = temp();
        Files.writeString(hex, HexUtils.bin2hex(Files.readAllBytes(file)));
        Assert.assertEquals(gp("--cert-in", hex.toString(), "--cert-verify", CA_PUBLIC), 0);
        Assert.assertEquals(gp("--cert-in", hex.toString(), "--cert-verify",
                HexUtils.bin2hex(GPCurve.secp256r1.encodePoint((ECPublicKey) Key.valueOf(CA_PUBLIC).getPublic().orElseThrow()))), 0);
    }

    @Test
    public void testDetachedDERSignature() throws Exception {
        // The body of a certificate whose signature is made elsewhere, written out for the signer
        final var file = temp();
        Assert.assertEquals(gp("--cert-new", "--cert-serial", "02", "--cert-ca", "|Kloc CA|", "--cert-subject", "|OCE|", "--cert-usage",
                "verification", "--cert-expires", "2030-01-01", "--cert-pubkey", CA_PUBLIC, "--cert-dtbs", "--cert-out", file.toString()), 0);
        final var dtbs = Files.readAllBytes(file);

        // An unsigned certificate body still reads like a signed one
        Assert.assertEquals(gp("--cert-dtbs-in", file.toString()), 0);

        // What openssl and JCA produce is a DER SEQUENCE, what the certificate carries is R||S
        final var signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(Key.valueOf(CA).getPrivate().orElseThrow());
        signer.update(dtbs);
        final var der = signer.sign();

        // From a file, the way openssl leaves it, and from the command line
        final var signature = temp();
        Files.write(signature, der);
        final var certificate = temp();
        Assert.assertEquals(gp("--cert-dtbs-in", file.toString(), "--cert-signature", signature.toString(), "--cert-out", certificate.toString()), 0);
        Assert.assertEquals(GPCertificate.parse(Files.readAllBytes(certificate)).signature().length, 64);
        Assert.assertEquals(gp("--cert-in", certificate.toString(), "--cert-verify", CA_PUBLIC), 0);

        final var same = temp();
        Assert.assertEquals(gp("--cert-dtbs-in", file.toString(), "--cert-signature", HexUtils.bin2hex(der), "--cert-out", same.toString()), 0);
        Assert.assertEquals(Files.readAllBytes(same), Files.readAllBytes(certificate));
    }

    @Test
    public void testPlainSignatureStartingWithDERTag() throws Exception {
        // The first byte of R is '30' in one signature out of 256
        final var file = temp();
        Assert.assertEquals(gp("--cert-new", "--cert-serial", "01", "--cert-ca", "|Kloc CA|", "--cert-subject", "|OCE|", "--cert-usage",
                "verification", "--cert-expires", "2030-01-01", "--cert-pubkey", CA_PUBLIC, "--cert-sign", CA, "--cert-out", file.toString()), 0);

        // '30' '3E' spans exactly the 64 bytes of R||S
        final var rs = GPCertificate.parse(Files.readAllBytes(file)).signature();
        rs[0] = 0x30;
        rs[1] = 0x3E;
        final var attached = temp();
        Assert.assertEquals(gp("--cert-in", file.toString(), "--cert-signature", HexUtils.bin2hex(rs), "--cert-out", attached.toString()), 0);
        Assert.assertEquals(GPCertificate.parse(Files.readAllBytes(attached)).signature(), rs);

        // Neither R||S of a known curve nor DER
        Assert.assertThrows(GPDataException.class, () -> gp("--cert-in", file.toString(), "--cert-signature", "30" + "AA".repeat(70)));

        // A DER signature of two 48 byte integers is P-384, not the P-256 of the stated CA curve
        final var p384 = "3064" + ("0230" + "7F" + "AA".repeat(47)).repeat(2);
        Assert.assertThrows(GPDataException.class, () -> gp("--cert-in", file.toString(), "--cert-signature", p384,
                "--cert-ca-curve", "secp256r1"));

        // Without a stated curve, the integers give the size
        final var wide = temp();
        Assert.assertEquals(gp("--cert-in", file.toString(), "--cert-signature", p384, "--cert-out", wide.toString()), 0);
        Assert.assertEquals(GPCertificate.parse(Files.readAllBytes(wide)).signature().length, 96);

        // brainpoolP512r1 integers are 64 bytes, two short of secp521r1: the curve has to be named
        final var bp512 = "308184" + ("0240" + "7F" + "AA".repeat(63)).repeat(2);
        Assert.assertThrows(GPDataException.class, () -> gp("--cert-in", file.toString(), "--cert-signature", bp512));

        final var named = temp();
        Assert.assertEquals(gp("--cert-in", file.toString(), "--cert-signature", bp512,
                "--cert-ca-curve", "brainpoolP512r1", "--cert-out", named.toString()), 0);
        Assert.assertEquals(GPCertificate.parse(Files.readAllBytes(named)).signature().length, 128);
    }

    @Test
    public void testRejections() throws Exception {
        final var file = temp();
        Assert.assertEquals(gp("--cert-new", "--cert-serial", "01", "--cert-ca", "|CA|", "--cert-subject", "|OCE|", "--cert-usage", "verification",
                "--cert-expires", "2030-01-01", "--cert-pubkey", CA_PUBLIC, "--cert-sign", CA, "--cert-out", file.toString()), 0);

        // The tool never emits a certificate whose signature does not cover its body
        Assert.assertThrows(IllegalArgumentException.class, () -> gp("--cert-in", file.toString(), "--cert-serial", "09"));
        // A public key point that is not on the given curve fails immediately; it never reaches a certificate
        Assert.assertThrows(IllegalArgumentException.class,
                () -> gp("--cert-new", "--cert-pubkey", "secp256r1:0401020304", "--cert-sign", CA));
        // Zero is not a private key
        Assert.assertThrows(IllegalArgumentException.class,
                () -> gp("--cert-new", "--cert-pubkey", CA_PUBLIC, "--cert-sign", "secp256r1:" + "00".repeat(32)));
        // Verifying a body the signature no longer covers fails; it does not throw
        final var tampered = temp();
        final var bytes = Files.readAllBytes(file);
        bytes[bytes.length - 1] ^= 0x01;
        Files.write(tampered, bytes);
        Assert.assertEquals(gp("--cert-in", tampered.toString(), "--cert-verify", CA_PUBLIC), 1);
    }
}
