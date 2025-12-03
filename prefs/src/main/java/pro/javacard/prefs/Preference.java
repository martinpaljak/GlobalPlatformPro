/*
 * Copyright (c) 2025 Martin Paljak <martin@martinpaljak.net>
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
package pro.javacard.prefs;

import java.lang.reflect.Type;
import java.util.Objects;
import java.util.function.Predicate;

public sealed interface Preference<V> permits Preference.Default, Preference.Parameter {
    String name();

    Type type();

    boolean readonly();

    default Predicate<V> validator() {
        return x -> true;
    }

    static <T> Default<T> of(String name, Class<T> type, T defaultValue, boolean readonly) {
        return new Default<>(name, type, defaultValue, readonly);
    }

    static <T> Parameter<T> parameter(String name, Class<T> type, boolean readonly) {
        return new Parameter<>(name, type, readonly);
    }

    record Default<V>(String name, Type type, V defaultValue, boolean readonly) implements Preference<V> {
        public Default {
            Objects.requireNonNull(defaultValue, "Must have a sane default value!");
        }
    }

    record Parameter<V>(String name, Type type, boolean readonly) implements Preference<V> {
    }
}
