package pro.javacard.gp.data;

import java.util.Arrays;

// Describes the position of data slice inside a byte array
public sealed interface ByteRangeLocation permits ByteRangeLocation.From, ByteRangeLocation.OffsetLength {
    record OffsetLength(int offset, int length) implements ByteRangeLocation {
    }

    record From(int offset) implements ByteRangeLocation {
    }

    static From from(int offset) {
        return new From(offset);
    }

    static OffsetLength from(int offset, int length) {
        return new OffsetLength(offset, length);
    }

    static byte[] extract(byte[] bytes, ByteRangeLocation location) {
        if (location instanceof OffsetLength ol) {
            return Arrays.copyOfRange(bytes, ol.offset(), ol.offset() + ol.length());
        } else if (location instanceof From from) {
            return Arrays.copyOfRange(bytes, from.offset(), bytes.length);
        }
        throw new IllegalArgumentException("Unknown ByteRangeLocation type");
    }
}
