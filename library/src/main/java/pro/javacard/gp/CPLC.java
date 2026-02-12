package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Optional;
import java.util.stream.Collectors;

public final class CPLC {
    private static final Logger logger = LoggerFactory.getLogger(CPLC.class);
    private final LinkedHashMap<Field, byte[]> values = new LinkedHashMap<>();

    private CPLC(byte[] data) {
        var offset = 0;
        for (Field f : Field.values()) {
            values.put(f, Arrays.copyOfRange(data, offset, offset + f.len));
            offset += f.len;
        }
    }

    public static CPLC fromBytes(byte[] data) throws GPDataException {
        if (data == null) {
            throw new IllegalArgumentException("data is null");
        }
        if (data.length < 0x2A) {
            throw new GPDataException("Input can't be valid CPLC if length is only %02X!".formatted(data.length), data);
        }
        // Remove tag, if present
        if (data[0] == (byte) 0x9f && data[1] == (byte) 0x7f && data[2] == (byte) 0x2A) {
            data = Arrays.copyOfRange(data, 3, data.length);
        }
        return new CPLC(data);
    }

    public byte[] get(final Field f) {
        return values.get(f);
    }

    @Override
    public String toString() {
        return Arrays.stream(Field.values()).map(i -> i.toString() + "=" + HexUtils.bin2hex(values.get(i))).collect(Collectors.joining(", ", "[CPLC: ", "]"));
    }

    public String toPrettyString() {
        return Arrays.stream(Field.values()).map(
                i -> i.toString() + "=" + HexUtils.bin2hex(values.get(i)) + (i.toString().endsWith("Date") ? " (" + toDateFailsafe(values.get(i)) + ")" : ""))
                .collect(Collectors.joining("\n      ", "CPLC: ", "\n"));
    }

    public enum Field {
        ICFabricator(2),
        ICType(2),
        OperatingSystemID(2),
        OperatingSystemReleaseDate(2),
        OperatingSystemReleaseLevel(2),
        ICFabricationDate(2),
        ICSerialNumber(4),
        ICBatchIdentifier(2),
        ICModuleFabricator(2),
        ICModulePackagingDate(2),
        ICCManufacturer(2),
        ICEmbeddingDate(2),
        ICPrePersonalizer(2),
        ICPrePersonalizationEquipmentDate(2),
        ICPrePersonalizationEquipmentID(4),
        ICPersonalizer(2),
        ICPersonalizationDate(2),
        ICPersonalizationEquipmentID(4);

        private final int len;

        Field(final int len) {
            this.len = len;
        }
    }

    public static Optional<LocalDate> toRelativeDate(final byte[] v, final LocalDate now) throws GPDataException {
        if ((v[0] == 0 && v[1] == 0) || (v[0] == (byte) 0xFF && v[1] == (byte) 0xFF)) {
            logger.debug("0x0000/0xFFFF does not represent a valid date");
            return Optional.empty();
        }
        final var sv = HexUtils.bin2hex(v);
        try {
            final var y = Integer.parseInt(sv.substring(0, 1));
            final var d = Integer.parseInt(sv.substring(1, 4));
            var base = 2020;
            if (y >= now.getYear() % 10 && d > now.getDayOfYear()) {
                base = 2010;
            }
            final LocalDate ld = LocalDate.ofYearDay(base + y, d);
            return Optional.of(ld);
        } catch (NumberFormatException | DateTimeException e) {
            logger.warn("Invalid CPLC date: " + sv);
            return Optional.empty();
        }
    }

    public static String toDateFailsafe(final byte[] v) {
        return toRelativeDate(v, LocalDate.now(ZoneOffset.UTC)).map(e -> e.format(DateTimeFormatter.ISO_LOCAL_DATE)).orElse("invalid date format");
    }

    public static byte[] today() {
        return dateToBytes(LocalDate.now(ZoneOffset.UTC));
    }

    public static byte[] dateToBytes(final LocalDate d) {
        return HexUtils.hex2bin("%d%03d".formatted(d.getYear() - 2020, d.getDayOfYear()));
    }
}
