/*
 * Copyright (c) 2018 Martin Paljak
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
package pro.javacard.capfile;

import java.util.Objects;
import java.util.Optional;

public class CAPPackage {
    final AID aid;
    final int minor;
    final int major;
    final String name;

    public CAPPackage(AID aid, int major, int minor) {
        this(aid, major, minor, null);
    }

    public CAPPackage(AID aid, int major, int minor, String name) {
        this.aid = aid;
        this.major = major;
        this.minor = minor;
        this.name = name;
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof CAPPackage) {
            CAPPackage o = (CAPPackage) other;
            return aid.equals(o.aid) && major == o.major && minor == o.minor;
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(aid, major, minor);
    }

    @Override
    public String toString() {
        return String.format("%-32s v%d.%d %s", aid, major, minor, getName().orElse(WellKnownAID.getName(aid).orElse("(unknown)")));
    }

    public String getVersionString() {
        return String.format("%d.%d", major, minor);
    }

    public AID getAid() {
        return aid;
    }

    public int getMinor() {
        return minor;
    }

    public int getMajor() {
        return major;
    }

    public Optional<String> getName() {
        return Optional.ofNullable(name);
    }
}
