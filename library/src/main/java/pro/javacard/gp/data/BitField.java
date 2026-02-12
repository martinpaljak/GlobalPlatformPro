/*
 * Copyright (c) 2025 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package pro.javacard.gp.data;

import apdu4j.core.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

// It would be nice if IDE helped with autocomplete and compiler helped with better compile time checks.
// We can't subclass enum, so instead make enum-s implement a simple interface, that give a "bitfield definition".
// Could also use BitSet and define a dictionary for "bit names" but this approach feels a bit better than either
// alternative or something combining records and BitSet-s etc.
public interface BitField<T extends Enum<T> & BitField<T>> {

    Logger log = LoggerFactory.getLogger(BitField.class);

    // Parse bytes, throw if RFU bits are set
    static <T extends Enum<T> & BitField<T>> Set<T> parse(Class<T> clazz, byte[] bytes, int... validLengths) {
        if (validLengths.length > 0) {
            final var valid = Arrays.stream(validLengths).anyMatch(l -> l == bytes.length);
            if (!valid) {
                throw new IllegalArgumentException(clazz.getSimpleName() + " must be " +
                        Arrays.toString(validLengths) + " bytes: " + HexUtils.bin2hex(bytes));
            }
        }
        final var r = parse(clazz, bytes);
        // Check for RFU
        for (var e : r) {
            if (e.def() instanceof Def.RFU) {
                throw new IllegalArgumentException("RFU bits set in " + clazz.getSimpleName() + ": " + HexUtils.bin2hex(bytes));
            }
        }
        return r;
    }

    // Encode to bytes with fixed length
    static <T extends Enum<T> & BitField<T>> byte[] encode(Set<T> fields, int length) {
        return toBytes(EnumSet.copyOf(fields), length);
    }

    static boolean has(byte[] bytes, Def f, boolean lax) {
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
                    // Expected in lax mode: e.g. 1-byte privilege field checked against 3-byte definitions
                    log.trace("Mask is for a byte that is more than bytes available, defaulting to false");
                    return false;
                } else {
                    throw new IllegalArgumentException("Need byte at index " + byteMask.n() + " but only " + bytes.length + " bytes provided");
                }
            }
            return (bytes[byteMask.n()] & byteMask.mask()) == byteMask.mask();
        } else if (f instanceof Def.RFU rfu) {
            return has(bytes, rfu.def(), true);
        }
        return false;
    }

    static <T extends Enum<T> & BitField<T>> Set<T> parse(Class<T> base, byte[] bytes) {
        final var result = EnumSet.noneOf(base);
        for (var e : base.getEnumConstants()) {
            if (has(bytes, e.def(), true)) {
                result.add(e);
                if (e.def() instanceof Def.RFU) {
                    log.warn("{} RFU bits set in {}", base.getName(), HexUtils.bin2hex(bytes));
                }
            }
        }
        return result;
    }

    static <T extends Enum<T> & BitField<T>> byte[] toBytes(Set<T> fields, int length) {
        final byte[] result = new byte[length];

        for (var field : fields) {
            final var def = field.def();
            if (def instanceof Def.Bits bits) {
                for (var bit : bits.bits()) {
                    final var byteIdx = bit >> 3;
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

    static <T extends Enum<T> & BitField<T>> byte[] toBytes(Set<T> fields) {
        final byte[] result = toBytes(fields, 16);

        // Trim trailing zeros
        var length = 16;
        while (length > 0 && result[length - 1] == 0) {
            length--;
        }

        final byte[] trimmed = new byte[length];
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
        final var byteIdx = (short) (offset + (bit >> 3)); // offset + bit / 8
        final var bitInByte = (byte) (7 - (bit & 7)); // 7 - (bit % 8)
        final var previous = (byte) ((buffer[byteIdx] >> bitInByte) & 1) == 1;
        buffer[byteIdx] = (byte) (buffer[byteIdx] | (byte) (1 << bitInByte));
        return previous;
    }

    static boolean get_bit(byte[] buffer, short offset, byte bit) {
        final var byteIdx = (short) (offset + (bit >> 3)); // offset + bit / 8
        final var bitInByte = (byte) (7 - (bit & 7)); // 7 - (bit % 8)
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

    // 1 based byte, bits are 8th...1st
    static Def.Bits byte_bit_rl(byte nthByte, int bit) {
        return bits((byte) ((nthByte - 1) * 8 + (8 - bit)));
    }

    static Def byte_mask(int n, int mask) {
        return new Def.ByteMask((byte) n, (byte) (mask & 0xFF));
    }

    // Calculate the length in bytes required to store the whole bitfield
    static <T extends Enum<T> & BitField<T>> int length(Class<T> clazz) {
        var max = 0;
        for (var e : clazz.getEnumConstants()) {
            final var len = e.def().length();
            if (len > max) {
                max = len;
            }
        }
        return max;
    }

    // BitField definition for the enum
    Def def();

    sealed interface Def permits Def.Bits, BitField.Def.ByteMask, BitField.Def.RFU {
        // Calculate the length in bytes required to store this definition
        default int length() {
            if (this instanceof Def.Bits bits) {
                // find the highest bit
                var max = 0;
                for (byte b : bits.bits()) {
                    final var v = b & 0xFF;
                    if (v > max) {
                        max = v;
                    }
                }
                return (max / 8) + 1;
            } else if (this instanceof Def.ByteMask byteMask) {
                return (byteMask.n() & 0xFF) + 1;
            } else if (this instanceof Def.RFU rfu) {
                return rfu.def().length();
            }
            throw new IllegalArgumentException("Unknown definition type: " + this);
        }

        // Present, if all bits are present
        record Bits(List<Byte> bits) implements Def {
            public Bits { bits = List.copyOf(bits); }
        }

        // Present, if n-th byte (0-based) has the mask.
        record ByteMask(byte n, byte mask) implements Def {}

        // Special type for bits that MUST NOT be set.
        record RFU(Def def) implements Def {}
    }
}
