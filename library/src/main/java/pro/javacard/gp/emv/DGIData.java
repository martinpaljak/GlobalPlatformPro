/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2025-present Martin Paljak, martin@martinpaljak.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package pro.javacard.gp.emv;

import apdu4j.core.HexUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// EMV builds on top of GlobalPlatform (remember, it was Visa Open Platform!)
public final class DGIData {

    public enum Type {
        PLAINTEXT, // plaintext
        PADDING, // encrypted with padding
        NOPADDING // encrypted without padding
    }

    private final byte[] tag;
    private final byte[] value;
    private final Type type;

    public DGIData(byte[] tag, byte[] value, Type type) {
        this.tag = Arrays.copyOf(tag, tag.length);
        this.value = Arrays.copyOf(value, value.length);
        this.type = type;
    }

    public byte[] tag() {
        return Arrays.copyOf(tag, tag.length);
    }

    public byte[] value() {
        return Arrays.copyOf(value, value.length);
    }

    public Type type() {
        return type;
    }

    public static byte[] length(int len) {
        if (len <= 254) {
            return new byte[]{(byte) len};
        } else {
            return new byte[]{(byte) 0xFF, (byte) (len >> 8), (byte) len};
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DGIData dgi = (DGIData) o;
        return Arrays.equals(tag, dgi.tag) && Arrays.equals(value, dgi.value) && type == dgi.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(tag), Arrays.hashCode(value), type);
    }

    @Override
    public String toString() {
        return "(" + type.name() + ") DGI " + HexUtils.bin2hex(tag) + "=" + HexUtils.bin2hex(value);
    }

    // Simple parser for "DGIXXXX=YY..YY" file. The information about the DGI type comes from an oracle.
    private static final Pattern LINE_PATTERN = Pattern.compile("^DGI([0-9a-fA-F]{4})=([0-9a-fA-F]*)$");

    public static List<DGIData> parse(Path filePath, Function<byte[], Type> typeOracle) throws IOException {
        var entries = new ArrayList<DGIData>();
        var lines = Files.readAllLines(filePath);
        for (var line : lines) {
            var s = line.trim();
            if (s.startsWith("//") || s.startsWith("#"))
                continue;
            Matcher matcher = LINE_PATTERN.matcher(s);
            if (!matcher.matches()) {
                throw new IOException("Invalid DGI file line: " + line);
            }

            byte[] tag = HexUtils.hex2bin(matcher.group(1));
            byte[] value = HexUtils.hex2bin(matcher.group(2));
            DGIData.Type type = typeOracle.apply(tag);
            entries.add(new DGIData(tag, value, type));
        }
        return entries;
    }
}
