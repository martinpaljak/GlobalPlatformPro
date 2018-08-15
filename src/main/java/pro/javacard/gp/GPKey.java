/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2017 Martin Paljak, martin@martinpaljak.net
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
package pro.javacard.gp;

import apdu4j.HexUtils;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

// Encapsulates a plaintext symmetric key used with GlobalPlatform
public final class GPKey {
    private Type type;
    private int version = 0; // 1..7f
    private int id = -1; // 0..7f
    private int length = -1;
    private transient byte[] bytes = null;

    // Create a key of given type and given bytes bytes
    public GPKey(byte[] v, Type type) {
        if (v.length != 16 && v.length != 24 && v.length != 32)
            throw new IllegalArgumentException("A valid key must be 16/24/32 bytes long");
        this.bytes = Arrays.copyOf(v, v.length);
        this.length = v.length;
        this.type = type;
    }

    // Raw key, that can be interpreted in any way.
    public GPKey(byte[] key) {
        this(key, Type.RAW);
    }

    // Creates a new key with a new version and id, based on key type and bytes of an existing key
    public GPKey(int version, int id, GPKey other) {
        this(other.bytes, other.type);
        this.version = version;
        this.id = id;
    }

    // Called when parsing KeyInfo template, no values present
    public GPKey(int version, int id, int length, int type) {
        this.version = version;
        this.id = id;
        this.length = length;
        // FIXME: these values should be encapsulated somewhere
        // FIXME: 0x81 is actually reserved according to GP
        // GP 2.2.1 11.1.8 Key Type Coding
        if (type == 0x80 || type == 0x81 || type == 0x82) {
            this.type = Type.DES3;
        } else if (type == 0x88) {
            this.type = Type.AES;
        } else if (type == 0xA1 || type == 0xA0) {
            this.type = Type.RSAPUB;
        } else if (type == 0x85) {
            this.type = Type.PSK;
        } else {
            throw new UnsupportedOperationException(String.format("Only AES, 3DES, PSK and RSA public keys are supported currently: 0x%02X", type));
        }
    }

    // Do shuffling as necessary
    private static byte[] resizeDES(byte[] key, int length) {
        if (length == 24) {
            byte[] key24 = new byte[24];
            System.arraycopy(key, 0, key24, 0, 16);
            System.arraycopy(key, 0, key24, 16, 8);
            return key24;
        } else {
            byte[] key8 = new byte[8];
            System.arraycopy(key, 0, key8, 0, 8);
            return key8;
        }
    }

    public int getID() {
        return id;
    }

    public int getVersion() {
        return version;
    }

    public byte[] getBytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    public int getLength() {
        return length;
    }

    public Type getType() {
        return type;
    }

    // Returns a Java key, usable in Ciphers
    // Only trick here is the size fiddling for DES
    public Key getKeyAs(Type type) {
        if (type == Type.DES) {
            return new SecretKeySpec(resizeDES(bytes, 8), "DES");
        } else if (type == Type.DES3) {
            return new SecretKeySpec(resizeDES(bytes, 24), "DESede");
        } else if (type == Type.AES) {
            return new SecretKeySpec(bytes, "AES");
        }
        throw new IllegalArgumentException("Can only create DES/3DES/AES keys");
    }

    public String toString() {
        StringBuffer s = new StringBuffer();
        s.append("type=" + type);
        if (version >= 1 && version <= 0x7f)
            s.append(" version=" + String.format("%d (0x%02X)", version, version));
        if (id >= 0 && id <= 0x7F)
            s.append(" id=" + String.format("%d (0x%02X)", id, id));
        if (bytes != null)
            s.append(" bytes=" + HexUtils.bin2hex(bytes));
        else
            s.append(" len=" + length);
        byte[] kcv = getKCV();
        if (kcv.length > 0) {
            s.append(" kcv=" + HexUtils.bin2hex(getKCV()));
        }
        return s.toString();
    }

    public byte[] getKCV() {
        if (type == Type.DES3) {
            return GPCrypto.kcv_3des(this);
        } else if (type == Type.AES) {
            return GPCrypto.scp03_key_check_value(this);
        } else {
            return new byte[0];
        }
    }

    // Change the type of a RAW key
    public void become(Type t) {
        if (type != Type.RAW)
            throw new IllegalStateException("Only RAW keys can become a new type");
        type = t;
    }

    public enum Type {
        RAW, DES, DES3, AES, RSAPUB, PSK;

        @Override
        public String toString() {
            if (this.name().equals("RSAPUB"))
                return "RSA";
            return super.toString();
        }
    }
}
