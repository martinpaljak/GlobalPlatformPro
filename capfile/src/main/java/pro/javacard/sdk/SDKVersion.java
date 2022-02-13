/**
 * Copyright (c) 2022 Martin Paljak
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package pro.javacard.sdk;

import java.util.Arrays;
import java.util.Optional;

public enum SDKVersion {
    V211("2.1.1"),
    V212("2.1.2"),
    V221("2.2.1"),
    V222("2.2.2"),
    V301("3.0.1"),
    V304("3.0.4"),
    V305("3.0.5"),
    V310("3.1.0");

    final String v;

    SDKVersion(String v) {
        this.v = v;
    }

    @Override
    public String toString() {
        return this.v;
    }

    public boolean isV3() {
        return this.name().startsWith("V3");
    }

    public boolean isOneOf(SDKVersion... versions) {
        for (SDKVersion v : versions)
            if (this.equals(v))
                return true;
        return false;
    }

    public static Optional<SDKVersion> fromVersion(String versionString) {
        return Arrays.stream(values()).filter(ver -> ver.v.equals(versionString)).findFirst();
    }
}
