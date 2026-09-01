// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gptool;

import apdu4j.core.HexBytes;
import apdu4j.core.HexUtils;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import pro.javacard.gp.GPCertificate;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPCurve;
import pro.javacard.gp.GPDataException;
import pro.javacard.gp.GPUtils;
import pro.javacard.tlv.Len;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVParseException;
import pro.javacard.tlv.Tag;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static pro.javacard.gptool.GPTool.verbose;

// GP certificates ('7F21') without a card: read, print, verify, construct and sign.
final class GPCertTool extends GPCommandLineInterface {

    // Tags of Amendment F v1.4 Table 6-1 and Amendment A v1.2 Table 3-6
    private static final Map<Integer, String> NAMES = Map.ofEntries(
            Map.entry(0x93, "Certificate Serial Number"),
            Map.entry(0x42, "CA Identifier"),
            Map.entry(0x5F20, "Subject Identifier"),
            Map.entry(0x95, "Key Usage"),
            Map.entry(0x5F25, "Effective Date"),
            Map.entry(0x5F24, "Expiration Date"),
            Map.entry(0x45, "Security Domain Image Number"),
            Map.entry(0x53, "Discretionary Data"),
            Map.entry(0x73, "Discretionary Data"),
            Map.entry(0xBF20, "Authorizations"),
            Map.entry(0x7F49, "Public Key"),
            Map.entry(0x5F37, "Signature"));

    private static final Tag SIGNATURE = Tag.ber(0x5F37);

    // A DER ECDSA signature: SEQUENCE of two INTEGER-s
    private static final Tag SEQUENCE = Tag.ber(0x30);
    private static final Tag INTEGER = Tag.ber(0x02);

    private static final List<OptionSpec<?>> FIELDS = List.of(OPT_CERT_SERIAL, OPT_CERT_CA, OPT_CERT_SUBJECT, OPT_CERT_USAGE, OPT_CERT_EFFECTIVE,
            OPT_CERT_EXPIRES, OPT_CERT_IMAGE_NUMBER, OPT_CERT_DISCRETIONARY, OPT_CERT_DISCRETIONARY_TLV, OPT_CERT_AUTHORIZATIONS, OPT_CERT_PUBKEY);

    private GPCertTool() {}

    // Any --cert-* option means an offline run, with no reader and no card
    static boolean isCertificateCommand(final OptionSet args) {
        return args.specs().stream().flatMap(s -> s.options().stream()).anyMatch(o -> o.startsWith("cert-"));
    }

    static int run(final OptionSet args) throws IOException, GeneralSecurityException {
        final var chain = args.has(OPT_CERT_IN) ? read(args.valueOf(OPT_CERT_IN)) : List.<GPCertificate>of();

        // Verifies against the given issuer, then along the chain
        var verified = true;
        if (args.has(OPT_CERT_VERIFY)) {
            var issuer = issuer(args);
            for (final var certificate : chain) {
                final var ok = certificate.verify(issuer);
                System.out.printf("%s: %s%n", certificate, ok ? "verified" : "SIGNATURE DOES NOT VERIFY");
                verified &= ok;
                issuer = certificate.publicKey();
            }
        }

        final var edited = FIELDS.stream().anyMatch(args::has);

        // No edit verb given: print what the file holds
        if (!edited && !args.has(OPT_CERT_NEW) && !args.has(OPT_CERT_SIGN) && !args.has(OPT_CERT_SIGNATURE)) {
            if (args.has(OPT_CERT_DTBS_IN)) {
                print(unsigned(bytes(args.valueOf(OPT_CERT_DTBS_IN))), "GP certificate, not signed yet");
            } else if (!args.has(OPT_CERT_VERIFY)) {
                for (var i = 0; i < chain.size(); i++) {
                    print(chain.get(i), "GP certificate %d/%d".formatted(i + 1, chain.size()));
                }
            }
            return verified ? 0 : 1;
        }

        // A signature only ever covers the body it was made over
        if (edited && !args.has(OPT_CERT_SIGN) && !args.has(OPT_CERT_SIGNATURE) && !args.has(OPT_CERT_DTBS)) {
            throw new IllegalArgumentException("Changing a certificate needs --cert-sign, --cert-signature or --cert-dtbs");
        }
        if (edited && args.has(OPT_CERT_DTBS_IN)) {
            throw new IllegalArgumentException("Fields are already fixed in the bytes to be signed");
        }
        if (chain.size() > 1) {
            throw new IllegalArgumentException("Can only change a single certificate, %d given".formatted(chain.size()));
        }

        // From an existing certificate, or from nothing with --cert-new
        final var builder = GPCertificate.builder();
        for (final var certificate : chain) {
            certificate.fields().stream().filter(f -> !SIGNATURE.equals(f.tag())).forEach(f -> builder.field(tag(f.tag()), f.value()));
        }
        apply(builder, args);

        // The bytes to be signed, for a signer that lives elsewhere; the digest goes to stderr
        if (args.has(OPT_CERT_DTBS)) {
            final var dtbs = builder.dtbs();
            final var digest = curve(args).digest();
            write(args, dtbs);
            System.err.printf("%s: %s%n", digest, HexUtils.bin2hex(MessageDigest.getInstance(digest).digest(dtbs)));
            return verified ? 0 : 1;
        }

        final GPCertificate certificate;
        if (args.has(OPT_CERT_DTBS_IN)) {
            certificate = GPCertificate.of(bytes(args.valueOf(OPT_CERT_DTBS_IN)), signature(args));
        } else if (args.has(OPT_CERT_SIGN)) {
            final var ca = args.valueOf(OPT_CERT_SIGN);
            certificate = builder.sign(ca.getPrivate().orElseThrow(() -> new IllegalArgumentException("No private key in " + ca)));
        } else {
            certificate = builder.signature(signature(args));
        }
        warn(certificate);
        write(args, certificate.encode());
        return verified ? 0 : 1;
    }

    // A Certificate Store ('BF21') is unwrapped to the chain it holds
    private static List<GPCertificate> read(final File file) throws IOException {
        return GPCertificate.parseChain(unwrap(bytes(file)));
    }

    // The bytes of a file, written as bytes or dumped as hex or base64
    private static byte[] bytes(final File file) throws IOException {
        final var bytes = Files.readAllBytes(file.toPath());
        if (binary(bytes)) {
            return bytes;
        }
        final var text = new String(bytes, StandardCharsets.US_ASCII).trim();
        try {
            return HexUtils.stringToBin(text);
        } catch (IllegalArgumentException hex) {
            try {
                return Base64.getMimeDecoder().decode(text);
            } catch (IllegalArgumentException base64) {
                throw new IllegalArgumentException("Could not read %s as bytes, hex or base64".formatted(file));
            }
        }
    }

    // Anything a hex or base64 dump cannot contain, which a certificate always has: it starts with '7F21'
    private static boolean binary(final byte[] bytes) {
        for (final var b : bytes) {
            if (b < 0x20 && b != '\n' && b != '\r' && b != '\t' || b == 0x7F) {
                return true;
            }
        }
        return bytes.length == 0;
    }

    // Amendment F v1.4 Table 7-4: the store is the same chain inside a 'BF21'
    private static byte[] unwrap(final byte[] bytes) {
        if (bytes.length < 2 || (bytes[0] & 0xFF) != 0xBF || (bytes[1] & 0xFF) != 0x21) {
            return bytes;
        }
        final var buffer = ByteBuffer.wrap(bytes);
        Tag.Codec.BER.decode(buffer);
        final var value = new byte[Len.ber(buffer)];
        buffer.get(value);
        return value;
    }

    // PEM key or certificate, a GP certificate, or a public key on the command line
    private static ECPublicKey issuer(final OptionSet args) throws IOException, GeneralSecurityException {
        final var value = args.valueOf(OPT_CERT_VERIFY);
        try {
            return publicKey(value);
        } catch (IllegalArgumentException e) {
            if (!new File(value).isFile()) {
                throw e;
            }
            // Not a PEM file, but a GP certificate; in a chain, the signer is the last one
            final var chain = read(new File(value));
            if (chain.isEmpty()) {
                throw new GPDataException("No certificate in " + value);
            }
            return chain.get(chain.size() - 1).publicKey();
        }
    }

    // R||S as given, or the DER SEQUENCE that JCA and openssl produce, from a file or the command line
    private static byte[] signature(final OptionSet args) throws IOException, GeneralSecurityException {
        final var given = args.valueOf(OPT_CERT_SIGNATURE);
        final var value = new File(given).isFile() ? bytes(new File(given)) : HexUtils.stringToBin(given);
        // The CA curve as given, else NIST: a brainpool CA has to be named
        final var curves = args.has(OPT_CERT_CA_CURVE) ? List.of(args.valueOf(OPT_CERT_CA_CURVE))
                : List.of(GPCurve.secp256r1, GPCurve.secp384r1, GPCurve.secp521r1);
        final var integers = der(value);
        if (integers.isPresent()) {
            final var length = orderLength(curves, integers.get());
            verbose("Converting DER signature to R||S of %d bytes".formatted(2 * length));
            return GPCrypto.der2rs(value, length);
        }
        // R||S is two order-wide integers, GPC 2.3.1 B.4.3
        if (curves.stream().anyMatch(c -> value.length == 2 * c.orderLength())) {
            return value;
        }
        throw new GPDataException("Signature is neither DER nor R||S", value);
    }

    // The two integers of a DER ECDSA signature
    private static Optional<List<TLV>> der(final byte[] value) {
        try {
            final var parsed = TLV.parse(value);
            if (parsed.size() == 1 && SEQUENCE.equals(parsed.get(0).tag())) {
                final var integers = List.copyOf(parsed.get(0).children());
                if (integers.size() == 2 && integers.stream().allMatch(i -> INTEGER.equals(i.tag()))) {
                    return Optional.of(integers);
                }
            }
        } catch (TLVParseException e) {
            verbose("Not a DER signature: " + e.getMessage());
        }
        return Optional.empty();
    }

    // The smallest curve the integers fit on
    private static int orderLength(final List<GPCurve> curves, final List<TLV> integers) {
        // The DER integers are signed and r or s may be short
        final var size = integers.stream().mapToInt(i -> (new BigInteger(1, i.value()).bitLength() + 7) / 8).max().orElseThrow();
        return curves.stream().mapToInt(GPCurve::orderLength).sorted().filter(l -> l == size || l == size + 1).findFirst()
                .orElseThrow(() -> new GPDataException("No curve for %d byte signature integers, state --cert-ca-curve".formatted(size)));
    }

    // P-256 wherever the CA curve is needed and not stated
    private static GPCurve curve(final OptionSet args) {
        if (args.has(OPT_CERT_CA_CURVE)) {
            return args.valueOf(OPT_CERT_CA_CURVE);
        }
        verbose("Assuming secp256r1");
        return GPCurve.secp256r1;
    }

    private static void apply(final GPCertificate.Builder builder, final OptionSet args) throws GeneralSecurityException {
        bytes(args, OPT_CERT_SERIAL).ifPresent(builder::serial);
        bytes(args, OPT_CERT_CA).ifPresent(builder::ca);
        bytes(args, OPT_CERT_SUBJECT).ifPresent(builder::subject);
        bytes(args, OPT_CERT_IMAGE_NUMBER).ifPresent(builder::imageNumber);
        bytes(args, OPT_CERT_DISCRETIONARY).ifPresent(builder::discretionary);
        bytes(args, OPT_CERT_DISCRETIONARY_TLV).ifPresent(builder::discretionaryTLV);
        bytes(args, OPT_CERT_AUTHORIZATIONS).ifPresent(builder::authorizations);
        optional(args, OPT_CERT_USAGE).ifPresent(builder::usage);
        optional(args, OPT_CERT_EFFECTIVE).ifPresent(builder::effective);
        optional(args, OPT_CERT_EXPIRES).ifPresent(builder::expires);
        if (args.has(OPT_CERT_PUBKEY)) {
            builder.publicKey(publicKey(args.valueOf(OPT_CERT_PUBKEY)));
        }
    }

    // PEM public key or certificate, or a public key on the command line
    private static ECPublicKey publicKey(final String value) {
        return ec(Key.valueOf(value).getPublic().orElse(null), value);
    }

    private static ECPublicKey ec(final PublicKey key, final String source) {
        if (key instanceof ECPublicKey ec) {
            return ec;
        }
        throw new IllegalArgumentException("No EC public key in " + source);
    }

    // Everything the tables disagree on or leave open is a warning, and the bytes are still emitted
    private static void warn(final GPCertificate certificate) {
        final var serial = certificate.serial().length;
        if (serial < 1 || serial > 16) {
            warning("Certificate Serial Number ('93') is %d bytes, the tables say 1-16".formatted(serial));
        }
        certificate.discretionary().filter(d -> d.length > 127)
                .ifPresent(d -> warning("Discretionary Data is %d bytes, the tables say 1-127".formatted(d.length)));
        if (certificate.authorizations().isPresent() && certificate.usage() == GPCertificate.Usage.VERIFICATION) {
            warning("Authorizations ('BF20') is specified for the OCE certificate, which has Key Usage '0080'");
        }
        if (GPCurve.forReference(certificate.curveReference()).isEmpty()) {
            warning("Key Parameter Reference '%02X' is not in GPC 2.3.1 Table B-2".formatted(certificate.curveReference()));
        }
    }

    private static void write(final OptionSet args, final byte[] encoded) throws IOException {
        if (args.has(OPT_CERT_OUT)) {
            final var file = args.valueOf(OPT_CERT_OUT).toPath();
            Files.write(file, args.has(OPT_CERT_HEX) ? HexUtils.bin2hex(encoded).getBytes(StandardCharsets.US_ASCII)
                    : args.has(OPT_CERT_BASE64) ? Base64.getEncoder().encode(encoded) : encoded);
            verbose("Wrote " + file);
        } else if (args.has(OPT_CERT_BIN)) {
            System.out.write(encoded);
            System.out.flush();
        } else {
            System.out.println(args.has(OPT_CERT_BASE64) ? Base64.getEncoder().encodeToString(encoded) : HexUtils.bin2hex(encoded));
        }
    }

    // A body without a signature, to read the fields of something that is still to be signed
    private static GPCertificate unsigned(final byte[] dtbs) {
        return GPCertificate.of(dtbs, new byte[0]);
    }

    private static void print(final GPCertificate certificate, final String title) {
        System.out.println(title);
        for (final var field : certificate.fields()) {
            if (SIGNATURE.equals(field.tag()) && field.value().length == 0) {
                continue;
            }
            final var tag = tag(field.tag());
            System.out.printf("  %-6s %-28s [%3d] %s%n", "'%s'".formatted(HexUtils.bin2hex(field.tag().bytes())), NAMES.getOrDefault(tag, "Unknown"),
                    field.value().length, decode(certificate, tag, field.value()));
        }
    }

    private static String decode(final GPCertificate certificate, final int tag, final byte[] value) {
        return switch (tag) {
            case 0x95 -> "%s (%s)".formatted(HexUtils.bin2hex(value), certificate.usage().name().toLowerCase(Locale.ROOT));
            case 0x5F24 -> certificate.expires().toString();
            case 0x5F25 -> certificate.effective().map(Object::toString).orElse(HexUtils.bin2hex(value));
            case 0x7F49 -> "%s on %s".formatted(HexUtils.bin2hex(certificate.publicKeyPoint()),
                    GPCurve.forReference(certificate.curveReference()).map(Enum::name)
                            .orElse("key parameter reference '%02X'".formatted(certificate.curveReference())));
            default -> GPUtils.bin2printable(value);
        };
    }

    private static Optional<byte[]> bytes(final OptionSet args, final OptionSpec<HexBytes> spec) {
        return optional(args, spec).map(HexBytes::value);
    }

    private static int tag(final Tag tag) {
        var value = 0;
        for (final var b : tag.bytes()) {
            value = (value << 8) | (b & 0xFF);
        }
        return value;
    }

    private static void warning(final String message) {
        System.err.println("Warning: " + message);
    }
}
