package pro.javacard.gp.data;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

public interface BitField<T extends Enum<T> & BitField<T>> {
    static boolean has(Def f, byte[] bytes, boolean lax) {
        if (f instanceof Def.Bits bits) {
            var yes = 0;
            for (var bit : bits.bits()) {
                if (get_bit(bit, bytes)) {
                    yes++;
                }
            }
            return yes == bits.bits().size();
        } else if (f instanceof Def.ByteMask byteMask) {
            if (byteMask.n() >= bytes.length) {
                if (lax) {
                    return false;
                } else {
                    throw new IllegalArgumentException("Need byte at index " + byteMask.n() + " but only " + bytes.length + " bytes provided");
                }
            }
            return (bytes[byteMask.n()] & byteMask.mask()) == byteMask.mask();
        } else if (f instanceof Def.RFU rfu) {
            return has(rfu.def(), bytes, true);
        }
        return false;
    }

    static <T extends Enum<T> & BitField<T>> Set<T> parse(Class<T> base, byte[] bytes) {
        var result = EnumSet.noneOf(base);
        for (var e : base.getEnumConstants()) {
            if (has(e.def(), bytes, true)) {
                result.add(e);
                if (e.name().equals("RFU")) {
                    //log.warn("{} RFU bits set in {}", base.getName(), Hex.toHexString(bytes));
                }
            }
        }
        return result;
    }

    static <T extends Enum<T> & BitField<T>> byte[] toBytes(EnumSet<T> fields, int length) {
        byte[] result = new byte[length];

        for (var field : fields) {
            Def def = field.def();
            if (def instanceof Def.Bits bits) {
                for (var bit : bits.bits()) {
                    int byteIdx = bit >> 3;
                    if (byteIdx < length) {
                        set_bit(bit, result);
                    }
                }
            } else if (def instanceof Def.ByteMask byteMask) {
                if (byteMask.n() < length) {
                    result[byteMask.n()] |= byteMask.mask();
                }
            } else if (def instanceof Def.RFU rfu) {
                // Skip RFU - don't encode reserved bits
                throw new IllegalArgumentException("RFU bits should never be serialized: " + rfu);
            }
        }

        return result;
    }

    static <T extends Enum<T> & BitField<T>> byte[] toBytes(EnumSet<T> fields) {
        byte[] result = toBytes(fields, 16);

        // Trim trailing zeros
        int length = 16;
        while (length > 0 && result[length - 1] == 0) {
            length--;
        }

        byte[] trimmed = new byte[length];
        System.arraycopy(result, 0, trimmed, 0, length);
        return trimmed;
    }

    static boolean set_bit(byte bit, byte[] bytes) {
        return set_bit(bytes, (short) 0, bit);
    }

    static boolean get_bit(byte bit, byte[] bytes) {
        return set_bit(bytes, (short) 0, bit);
    }

    // JC variants
    static boolean set_bit(byte[] buffer, short offset, byte bit) {
        short byteIdx = (short) (offset + (bit >> 3));  // offset + bit / 8
        byte bitInByte = (byte) (7 - (bit & 7));  // 7 - (bit % 8)
        boolean previous = (byte) ((buffer[byteIdx] >> bitInByte) & 1) == 1;
        buffer[byteIdx] = (byte) (buffer[byteIdx] | (byte) (1 << bitInByte));
        return previous;
    }

    static boolean get_bit(byte[] buffer, short offset, byte bit) {
        short byteIdx = (short) (offset + (bit >> 3));  // offset + bit / 8
        byte bitInByte = (byte) (7 - (bit & 7));  // 7 - (bit % 8)
        return (byte) ((buffer[byteIdx] >> bitInByte) & 1) == 1;
    }


    // n-th bit from the left
    static Def.Bits bit(int n) {
        return bits((byte) n);
    }

    // bits from the left
    static Def.Bits bits(int... bits) {
        return new Def.Bits(Arrays.stream(bits).mapToObj(i -> (byte) i).toList());
    }

    static Def.Bits byte_bit(int nthByte, int bit) {
        return bits((byte) (nthByte * 8 + bit));
    }

    // 1 based byte, bits are 8th..1st
    static Def.Bits byte_bit_rl(byte nthByte, int bit) {
        return bits((byte) ((nthByte - 1) * 8 + (8 - bit)));
    }

    static Def byte_mask(int n, int mask) {
        return new Def.ByteMask((byte) n, (byte) (mask & 0xFF));
    }

    // BitField definition for the enum
    Def def();

    sealed interface Def permits Def.Bits, BitField.Def.ByteMask, BitField.Def.RFU {
        // Present, if all bits are present
        record Bits(List<Byte> bits) implements Def {
            public Bits {
                bits = List.copyOf(bits);
            }
        }

        // Present, if n-th byte (0-based) has the mask.
        record ByteMask(byte n, byte mask) implements Def {
        }

        // Special type for bits that MUST NOT be set.
        record RFU(Def def) implements Def {
        }
    }
}
