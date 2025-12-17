package pro.javacard.tlv;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

// BER-TLV tag (ISO 7816-4)
public record BERTag(byte[] bytes) implements Tag {

    public BERTag {
        bytes = validate(bytes).clone();
    }

    @Override
    public byte[] bytes() {
        return bytes.clone();
    }

    static byte[] validate(byte[] value) {
        Objects.requireNonNull(value, "tag cannot be null");

        if (value.length == 0 || value.length > 4) {
            throw new IllegalArgumentException("Invalid tag length: " + value.length);
        }

        // Multi-byte tags: first byte must have all lower 5 bits set (0x1F)
        if (value.length > 1 && (value[0] & 0x1F) != 0x1F) {
            throw new IllegalArgumentException("Multi-byte tag must have first byte with 0x1F");
        }

        // Middle bytes must have continuation bit (0x80) set
        for (int i = 1; i < value.length - 1; i++) {
            if ((value[i] & 0x80) == 0) {
                throw new IllegalArgumentException("Tag continuation byte missing 0x80 bit");
            }
        }

        // Last byte must NOT have continuation bit
        if (value.length > 1 && (value[value.length - 1] & 0x80) != 0) {
            throw new IllegalArgumentException("Tag last byte should not have 0x80 bit");
        }
        return value;
    }

    public boolean isConstructed() {
        return (bytes[0] & 0x20) == 0x20;
    }

    // Parse from buffer, only move position if successful
    static BERTag parse(ByteBuffer buffer) {
        var bytes = new byte[4];
        var pos = buffer.position();
        var len = 0;

        var b = buffer.get(pos);
        bytes[len++] = b;

        if ((b & 0x1F) == 0x1F) {
            for (int i = 1; i < 4; i++) {
                b = buffer.get(pos + i);
                bytes[len++] = b;
                if ((b & 0x80) == 0) {
                    break;
                }
            }
        }
        // Throws IllegalArgumentException if not valid
        var tag = new BERTag(Arrays.copyOf(bytes, len));

        // Advance position on success only.
        buffer.position(pos + len);
        return tag;
    }

    @Override
    public String toString() {
        return toHex();
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof BERTag other && Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
