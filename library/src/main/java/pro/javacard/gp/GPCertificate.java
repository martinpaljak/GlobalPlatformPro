// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import apdu4j.core.HexUtils;
import pro.javacard.tlv.Len;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.function.Predicate;

// GlobalPlatform certificate (tag '7F21'), as used by SCP11 (Amendment F v1.4 Table 6-1) and by the
// CASD of Amendment A v1.2 (Table 3-6). In both, tag '5F37' is last and its signature covers every
// field preceding it in the order they appear, so the signed bytes are kept as they arrived and never
// re-encoded. The certificate with message recovery of Amendment A Table 3-4 is a different format
// and is not read here: it signs a reordered set and carries tag '5F38' after the signature.
public final class GPCertificate {

    private static final Tag CERTIFICATE = Tag.ber(0x7F21);
    private static final Tag SERIAL = Tag.ber(0x93);
    private static final Tag CA = Tag.ber(0x42);
    private static final Tag SUBJECT = Tag.ber(0x5F20);
    private static final Tag USAGE = Tag.ber(0x95);
    private static final Tag EFFECTIVE = Tag.ber(0x5F25);
    private static final Tag EXPIRES = Tag.ber(0x5F24);
    private static final Tag IMAGE_NUMBER = Tag.ber(0x45);
    private static final Tag DISCRETIONARY = Tag.ber(0x53);
    private static final Tag DISCRETIONARY_TLV = Tag.ber(0x73);
    private static final Tag AUTHORIZATIONS = Tag.ber(0xBF20);
    private static final Tag PUBLIC_KEY = Tag.ber(0x7F49);
    private static final Tag SIGNATURE = Tag.ber(0x5F37);
    private static final Tag POINT = Tag.ber(0xB0);
    private static final Tag CURVE = Tag.ber(0xF0);

    // The two table orders merged: '45' is only in Amendment A v1.2 Table 3-6, 'BF20' only in
    // Amendment F v1.4 Table 6-1. Anything else is emitted last.
    private static final List<Tag> ORDER = List.of(SERIAL, CA, SUBJECT, USAGE, EFFECTIVE, EXPIRES, IMAGE_NUMBER,
            DISCRETIONARY, DISCRETIONARY_TLV, AUTHORIZATIONS, PUBLIC_KEY);

    // Mandatory in every profile of the format
    private static final List<Tag> MANDATORY = List.of(SERIAL, CA, SUBJECT, USAGE, EXPIRES, PUBLIC_KEY);

    // Key Usage of tag '95', see GPC v2.3.1 11.1.9
    public enum Usage {
        VERIFICATION(0x8200), // Table 11-17: b8 verification, b2 digital signature
        AGREEMENT(0x0080); // Table 11-18: b8 key agreement

        // The first byte of Table 11-17 in the high half, the second byte of Table 11-18 in the low half
        private final int bits;

        Usage(final int bits) {
            this.bits = bits;
        }

        byte[] encode() {
            return (bits & 0xFF) == 0 ? new byte[] { (byte) (bits >> 8) } : new byte[] { (byte) (bits >> 8), (byte) bits };
        }

        static Usage of(final byte[] value) {
            if (value.length < 1 || value.length > 2) {
                throw new GPDataException("Invalid key usage", value);
            }
            // "If only the first byte is provided or available, then the second byte shall be
            // assumed to have a value of '00'"
            final var bits = ((value[0] & 0xFF) << 8) | (value.length > 1 ? value[1] & 0xFF : 0);
            for (final var usage : values()) {
                if (usage.bits == bits) {
                    return usage;
                }
            }
            throw new GPDataException("Unknown key usage", value);
        }
    }

    // Where a field sits in the body: start of the tag, then the range of its value
    private record Span(int start, int from, int to) {}

    private final byte[] body;
    private final Map<Tag, Span> index;

    private GPCertificate(final byte[] body) {
        this.body = body;
        this.index = index(body);

        missing(index::containsKey).ifPresent(m -> {
            throw new GPDataException(m, body);
        });
        if (index.containsKey(DISCRETIONARY) && index.containsKey(DISCRETIONARY_TLV)) {
            throw new GPDataException("Certificate has both '53' and '73' discretionary data", body);
        }
    }

    // Walks a sequence of TLVs without descending into any of them: tag 'B0' carries the constructed
    // bit, but its value is a point, not TLV.
    private static Map<Tag, Span> spans(final byte[] data) {
        final var spans = new LinkedHashMap<Tag, Span>();
        final var buffer = ByteBuffer.wrap(data);
        while (buffer.hasRemaining()) {
            final var start = buffer.position();
            final Tag tag;
            final int from;
            final int to;
            try {
                tag = Tag.Codec.BER.decode(buffer);
                final var length = Len.ber(buffer);
                from = buffer.position();
                to = from + length;
                buffer.position(to);
            } catch (RuntimeException e) {
                throw new GPDataException("Could not parse certificate field: " + e.getMessage(), data);
            }
            if (spans.put(tag, new Span(start, from, to)) != null) {
                throw new GPDataException("Duplicate tag " + tag.toHex(), data);
            }
        }
        return spans;
    }

    private static Map<Tag, Span> index(final byte[] body) {
        final var spans = spans(body);
        final var signature = spans.get(SIGNATURE);
        if (signature == null) {
            throw new GPDataException("Certificate has no signature", body);
        }
        if (signature.to() != body.length) {
            throw new GPDataException("Certificate has fields after the signature", body);
        }
        return Collections.unmodifiableMap(spans);
    }

    // A certificate from a signature made elsewhere over the bytes of Builder.dtbs()
    public static GPCertificate of(final byte[] dtbs, final byte[] signature) {
        return new GPCertificate(GPUtils.concatenate(dtbs, TLV.of(SIGNATURE, signature).encode()));
    }

    public static GPCertificate parse(final byte[] tlv) {
        final var buffer = ByteBuffer.wrap(tlv);
        final var certificate = parse(buffer);
        if (buffer.hasRemaining()) {
            throw new GPDataException("Trailing data after certificate", tlv);
        }
        return certificate;
    }

    // Certificates as concatenated in PERFORM SECURITY OPERATION data (Amendment F v1.4 Table 7-12)
    // or in the value of an SCP11 Certificate Store, tag 'BF21' (Table 7-4)
    public static List<GPCertificate> parseChain(final byte[] tlvs) {
        final var buffer = ByteBuffer.wrap(tlvs);
        final var chain = new ArrayList<GPCertificate>();
        while (buffer.hasRemaining()) {
            chain.add(parse(buffer));
        }
        return List.copyOf(chain);
    }

    private static GPCertificate parse(final ByteBuffer buffer) {
        final Tag tag;
        final byte[] body;
        try {
            tag = Tag.Codec.BER.decode(buffer);
            body = new byte[Len.ber(buffer)];
            buffer.get(body);
        } catch (RuntimeException e) {
            throw new GPDataException("Could not parse certificate: " + e.getMessage(), e);
        }
        if (!CERTIFICATE.equals(tag)) {
            throw new GPDataException("Not a certificate: " + tag.toHex());
        }
        return new GPCertificate(body);
    }

    private byte[] value(final Span span) {
        return Arrays.copyOfRange(body, span.from(), span.to());
    }

    private Optional<byte[]> optional(final Tag tag) {
        return Optional.ofNullable(index.get(tag)).map(this::value);
    }

    private byte[] required(final Tag tag) {
        return optional(tag).orElseThrow(() -> new GPDataException("Certificate is missing tag " + tag.toHex(), body));
    }

    private byte[] child(final Tag parent, final Tag child) {
        final var value = required(parent);
        final var span = spans(value).get(child);
        if (span == null) {
            throw new GPDataException("No " + child.toHex() + " in " + parent.toHex(), value);
        }
        return Arrays.copyOfRange(value, span.from(), span.to());
    }

    public byte[] serial() {
        return required(SERIAL);
    }

    public byte[] ca() {
        return required(CA);
    }

    public byte[] subject() {
        return required(SUBJECT);
    }

    public Usage usage() {
        return Usage.of(required(USAGE));
    }

    public Optional<LocalDate> effective() {
        return optional(EFFECTIVE).map(GPCertificate::date);
    }

    public LocalDate expires() {
        return date(required(EXPIRES));
    }

    // Security Domain Image Number of the CASD certificates
    public Optional<byte[]> imageNumber() {
        return optional(IMAGE_NUMBER);
    }

    public Optional<byte[]> discretionary() {
        return optional(DISCRETIONARY).or(() -> optional(DISCRETIONARY_TLV));
    }

    // Authorization rules of Amendment F v1.4 Table B-1
    public Optional<byte[]> authorizations() {
        return optional(AUTHORIZATIONS);
    }

    public byte[] publicKeyPoint() {
        return child(PUBLIC_KEY, POINT);
    }

    // Key Parameter Reference of GPC v2.3.1 Table B-2
    public int curveReference() {
        return reference(child(PUBLIC_KEY, CURVE));
    }

    public ECPublicKey publicKey() throws GeneralSecurityException {
        final var reference = curveReference();
        return GPCurve.forReference(reference)
                .orElseThrow(() -> new GPDataException("No curve for key parameter reference %02X".formatted(reference)))
                .toPublicKey(publicKeyPoint());
    }

    public byte[] signature() {
        return required(SIGNATURE);
    }

    // Every field in the order it was encoded, tags this class does not model included
    public List<TLV> fields() {
        return index.entrySet().stream().map(e -> TLV.of(e.getKey(), value(e.getValue()))).toList();
    }

    // Everything before tag '5F37', exactly as it arrived
    public byte[] signedData() {
        return Arrays.copyOf(body, index.get(SIGNATURE).start());
    }

    public boolean verify(final ECPublicKey issuer) throws GeneralSecurityException {
        return GPCrypto.ecdsa_plain_verify(issuer, signedData(), signature());
    }

    public byte[] encode() {
        return TLV.of(CERTIFICATE, body).encode();
    }

    // The value of any field, for tags this class does not model
    public Optional<byte[]> field(final int tag) {
        return optional(Tag.ber(tag));
    }

    // YYYYMMDD in BCD, which is the hex representation of the four bytes
    private static LocalDate date(final byte[] bcd) {
        if (bcd.length != 4) {
            throw new GPDataException("Invalid date", bcd);
        }
        try {
            return LocalDate.parse(HexUtils.bin2hex(bcd), DateTimeFormatter.BASIC_ISO_DATE);
        } catch (DateTimeParseException e) {
            throw new GPDataException("Invalid date", bcd);
        }
    }

    private static byte[] date(final LocalDate date) {
        return HexUtils.hex2bin(date.format(DateTimeFormatter.BASIC_ISO_DATE));
    }

    // One or two bytes, most significant first
    private static int reference(final byte[] value) {
        if (value.length < 1 || value.length > 2) {
            throw new GPDataException("Invalid key parameter reference", value);
        }
        return value.length == 1 ? value[0] & 0xFF : ((value[0] & 0xFF) << 8) | (value[1] & 0xFF);
    }

    private static byte[] reference(final int reference) {
        if (reference < 0 || reference > 0xFFFF) {
            throw new IllegalArgumentException("Key parameter reference out of range: " + reference);
        }
        return reference <= 0xFF ? new byte[] { (byte) reference } : new byte[] { (byte) (reference >> 8), (byte) reference };
    }

    private static Optional<String> missing(final Predicate<Tag> present) {
        return MANDATORY.stream().filter(t -> !present.test(t)).findFirst().map(t -> "Certificate is missing tag " + t.toHex());
    }

    private static int rank(final Tag tag) {
        final var i = ORDER.indexOf(tag);
        return i < 0 ? ORDER.size() : i;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final Map<Tag, byte[]> fields = new LinkedHashMap<>();

        private Builder() {}

        public Builder serial(final byte[] serial) {
            return field(SERIAL, serial);
        }

        public Builder ca(final byte[] ca) {
            return field(CA, ca);
        }

        public Builder subject(final byte[] subject) {
            return field(SUBJECT, subject);
        }

        public Builder usage(final Usage usage) {
            return field(USAGE, usage.encode());
        }

        public Builder effective(final LocalDate date) {
            return field(EFFECTIVE, date(date));
        }

        public Builder expires(final LocalDate date) {
            return field(EXPIRES, date(date));
        }

        public Builder imageNumber(final byte[] number) {
            return field(IMAGE_NUMBER, number);
        }

        // Tag '53', of unspecified format
        public Builder discretionary(final byte[] data) {
            return field(DISCRETIONARY, data);
        }

        // Tag '73', BER-TLV encoded
        public Builder discretionaryTLV(final byte[] data) {
            return field(DISCRETIONARY_TLV, data);
        }

        // Authorization rules of Amendment F v1.4 Table B-1
        public Builder authorizations(final byte[] rules) {
            return field(AUTHORIZATIONS, rules);
        }

        public Builder publicKey(final ECPublicKey key) {
            final var curve = GPCurve.forKey(key)
                    .orElseThrow(() -> new IllegalArgumentException("No key parameter reference for the curve of the key"));
            return publicKey(curve.encodePoint(key), curve.reference());
        }

        public Builder publicKey(final byte[] point, final int reference) {
            return field(PUBLIC_KEY, TLV.encode(TLV.of(POINT, point), TLV.of(CURVE, reference(reference))));
        }

        // Any other field, for tags this class does not model
        public Builder field(final int tag, final byte[] value) {
            return field(Tag.ber(tag), value);
        }

        private Builder field(final Tag tag, final byte[] value) {
            if (SIGNATURE.equals(tag)) {
                throw new IllegalArgumentException("The signature is added by sign()");
            }
            fields.put(tag, value.clone());
            return this;
        }

        // The bytes to be signed, for a signer that lives elsewhere
        public byte[] dtbs() {
            missing(fields::containsKey).ifPresent(m -> {
                throw new IllegalStateException(m);
            });
            return TLV.encode(fields.entrySet().stream()
                    .sorted(Comparator.comparingInt((Map.Entry<Tag, byte[]> e) -> rank(e.getKey())))
                    .map(e -> TLV.of(e.getKey(), e.getValue())).toList());
        }

        // Completes the certificate with a signature made over dtbs()
        public GPCertificate signature(final byte[] signature) {
            return of(dtbs(), signature);
        }

        public GPCertificate sign(final PrivateKey ca) throws GeneralSecurityException {
            return signature(GPCrypto.ecdsa_plain(ca, dtbs()));
        }
    }

    @Override
    public String toString() {
        return "GP certificate %s for %s by %s, expires %s".formatted(HexUtils.bin2hex(serial()),
                HexUtils.bin2hex(subject()), HexUtils.bin2hex(ca()), expires());
    }

    @Override
    public boolean equals(final Object o) {
        return o instanceof GPCertificate other && Arrays.equals(body, other.body);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(body);
    }
}
