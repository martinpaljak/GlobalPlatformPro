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

import java.util.*;

public final class Preferences {
    private final Map<Preference<?>, Object> values;
    // Registry allows to slurp in known preferences from a file.
    private static final Map<String, Preference<?>> REGISTRY = new HashMap<>();

    public Preferences() {
        this.values = Map.of();
    }

    private Preferences(Map<Preference<?>, Object> values) {
        // .copyOf() assures that there are no null values
        this.values = Map.copyOf(values);
    }

    // Only allows non-null overrides for preferences that have default values
    public <V> Preferences with(Preference<V> key, V value) {
        if (value == null) {
            throw new IllegalArgumentException("Cannot set null outcome for preference '" + key.name() + "'");
        }
        if (!key.validator().test(value)) {
            throw new IllegalArgumentException("Value for preference '" + key.name() + "' fails validation: " + value);
        }
        Map<Preference<?>, Object> newValues = new HashMap<>();
        newValues.put(key, value);
        // Calling merge will take care of readonly preferences
        return merge(new Preferences(newValues));
    }

    public <V> Preferences without(Preference<V> key) {
        if (key.readonly()) {
            throw new IllegalArgumentException("Can't remove readonly preference!");
        }
        if (!values.containsKey(key)) {
            return this;
        }
        Map<Preference<?>, Object> newValues = new HashMap<>(values);
        newValues.remove(key);
        return new Preferences(newValues);
    }

    // Always returns non-null: either the explicit override or the default outcome
    @SuppressWarnings("unchecked")
    public <V> V get(Preference.Default<V> key) {
        V value = (V) values.get(key);
        return value != null ? value : key.defaultValue();
    }

    // Returns empty Optional when using default, present Optional when explicitly overridden
    @SuppressWarnings("unchecked")
    public <V> Optional<V> valueOf(Preference<V> key) {
        // We don't allow null values, so the optional is empty only
        // if the preference is not explicitly established
        return Optional.ofNullable((V) values.get(key));
    }

    // Add all keys from other to this
    public Preferences merge(Preferences other) {
        Map<Preference<?>, Object> newValues = new HashMap<>(this.values);
        for (Map.Entry<Preference<?>, Object> entry : other.values.entrySet()) {
            Preference<?> key = entry.getKey();
            if (key.readonly() && this.values.containsKey(key)) {
                // Skip readonly preferences that already exist in this instance
                //log.warn("Trying to overwrite read-only preference " + key);
                continue;
            }
            newValues.put(key, entry.getValue());
        }
        return new Preferences(newValues);
    }

    public Set<Preference<?>> keys() {
        return values.keySet();
    }

    public boolean isEmpty() {
        return values.isEmpty();
    }

    public int size() {
        return values.size();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Preferences{");
        for (var k : values.entrySet()) {
            sb.append(k.getKey().name());
            sb.append("(");
            sb.append(k.getKey().type().getTypeName());
            sb.append(")");
            sb.append("=");
            if (k.getValue() instanceof byte[] bytes) {
                sb.append(HexFormat.of().formatHex(bytes));
            } else {
                sb.append(k.getValue());
            }
            sb.append(";");
        }
        sb.append("}");
        return sb.toString();
    }


    // For parameters (no default outcome)
    public static <T> Preference.Parameter<T> register(String name, Class<T> type, boolean readonly) {
        Preference.Parameter<T> preference = Preference.parameter(name, type, readonly);
        REGISTRY.put(preference.name(), preference);
        return preference;
    }

    // For parameters (readonly by default)
    public static <T> Preference.Parameter<T> register(String name, Class<T> type) {
        return register(name, type, true);
    }

    // For preferences with default values
    public static <T> Preference.Default<T> register(String name, Class<T> type, T defaultValue, boolean readonly) {
        Preference.Default<T> preference = Preference.of(name, type, defaultValue, readonly);
        REGISTRY.put(preference.name(), preference);
        return preference;
    }

    // For preferences with default values (not readonly by default)
    public static <T> Preference.Default<T> register(String name, Class<T> type, T defaultValue) {
        return register(name, type, defaultValue, false);
    }
}
