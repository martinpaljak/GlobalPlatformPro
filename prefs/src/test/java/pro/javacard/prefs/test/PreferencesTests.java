package pro.javacard.prefs.test;

import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.prefs.Preference;
import pro.javacard.prefs.Preferences;

import java.util.Optional;
import java.util.Set;

public class PreferencesTests {

    // Test preferences
    private static final Preference.Default<String> NAME = Preference.of("name", String.class, "default", false);
    private static final Preference.Default<String> READONLY_PREF = Preference.of("readonly", String.class, "readonly_default", true);

    @Test
    void testMergeWithReadonlyPreference() {
        final var prefs1 = new Preferences().with(READONLY_PREF, "existing");
        final var prefs2 = new Preferences().with(READONLY_PREF, "new_value");

        final var result = prefs1.merge(prefs2);

        Assert.assertEquals(result.get(READONLY_PREF), "existing");
    }

    @Test
    void testMergeReadonlyIntoEmpty() {
        final var empty = new Preferences();
        final var withReadonly = new Preferences().with(READONLY_PREF, "outcome");

        final var result = empty.merge(withReadonly);

        Assert.assertEquals(result.get(READONLY_PREF), "outcome");
    }

    @Test
    void testReadonlyPreferenceCreation() {
        Assert.assertTrue(READONLY_PREF.readonly());
        Assert.assertFalse(NAME.readonly());
    }

    @Test
    void testReadonlyPreferenceRemoval() {
        final var withReadonly = new Preferences().with(READONLY_PREF, "outcome");
        Assert.assertThrows(IllegalArgumentException.class, () -> {
            withReadonly.without(READONLY_PREF);
        });
    }

    @Test
    void testGetReturnsDefaultValues() {
        final var pref1 = Preference.of("pref1", Boolean.class, false, false);
        final var pref2 = Preference.of("pref2", Boolean.class, true, false);
        final var prefs = new Preferences();

        Assert.assertTrue(prefs.get(pref2));
        Assert.assertFalse(prefs.get(pref1));
    }

    @Test
    void testValueOfReturnsEmptyForDefaults() {
        final var pref1 = Preference.of("pref1", Boolean.class, false, false);
        final var pref2 = Preference.of("pref2", Boolean.class, true, false);
        final var prefs = new Preferences();

        Assert.assertEquals(Optional.empty(), prefs.valueOf(pref2));
        Assert.assertEquals(Optional.empty(), prefs.valueOf(pref1));
    }

    @Test
    void testWithOverridesValue() {
        final var pref1 = Preference.of("pref1", Boolean.class, false, false);
        final var prefs = new Preferences().with(pref1, true);

        Assert.assertTrue(prefs.get(pref1));
        Assert.assertEquals(Optional.of(Boolean.TRUE), prefs.valueOf(pref1));
    }

    @Test
    void testWithoutRemovesOverride() {
        final var pref1 = Preference.of("pref1", Boolean.class, false, false);
        final var pref2 = Preference.of("pref2", Boolean.class, true, false);
        var prefs = new Preferences().with(pref1, true);

        Assert.assertEquals(prefs, prefs.without(pref2)); // removing non-existent key returns same instance
        Assert.assertTrue(prefs.valueOf(pref2).isEmpty());
        Assert.assertTrue(prefs.valueOf(pref1).isPresent());

        prefs = prefs.without(pref1);
        Assert.assertTrue(prefs.valueOf(pref1).isEmpty());
        Assert.assertTrue(prefs.isEmpty());
    }

    @Test
    void testWithNullValueThrowsException() {
        final var pref1 = Preference.of("pref1", Boolean.class, false, false);

        Assert.assertThrows(IllegalArgumentException.class, () -> new Preferences().with(pref1, null));
    }

    @Test
    void testParameterWithoutValue() {
        final var param = Preference.parameter("optional-setting", String.class, false);
        final var prefs = new Preferences();

        Assert.assertTrue(prefs.valueOf(param).isEmpty());
    }

    @Test
    void testParameterWithValue() {
        final var param = Preference.parameter("optional-setting", String.class, false);
        final var prefs = new Preferences().with(param, "configured-outcome");

        Assert.assertEquals(prefs.valueOf(param).get(), "configured-outcome");
        Assert.assertTrue(prefs.valueOf(param).isPresent());
    }

    @Test
    void testParameterCannotUseGet() {
        final var param = Preference.parameter("optional-setting", String.class, false);
        final var prefs = new Preferences().with(param, "outcome");

        // This should not compile - param is Parameter<String>, not Default<String>
        // prefs.get(param); // Compilation error - good!
    }

    @Test
    void testReadonlyParameter() {
        final var param = Preference.parameter("readonly-param", String.class, true);
        final var prefs1 = new Preferences().with(param, "initial");
        final var prefs2 = new Preferences().with(param, "override");

        final var merged = prefs1.merge(prefs2);

        Assert.assertEquals(merged.valueOf(param).get(), "initial");
        Assert.assertTrue(param.readonly());
    }

    @Test
    void testParameterWithNullValueThrows() {
        final var param = Preference.parameter("param", String.class, false);

        Assert.assertThrows(IllegalArgumentException.class, () -> new Preferences().with(param, null));
    }

    @Test
    void testMixedDefaultsAndParameters() {
        final var defaultPref = Preference.of("default", String.class, "default-outcome", false);
        final var param = Preference.parameter("param", String.class, false);

        final var prefs = new Preferences()
                .with(defaultPref, "overridden")
                .with(param, "param-outcome");

        Assert.assertEquals(prefs.get(defaultPref), "overridden");
        Assert.assertEquals(prefs.valueOf(param).get(), "param-outcome");
        Assert.assertEquals(prefs.size(), 2);
    }

    @Test
    public void testValidationSuccess() {
        final var validated = Preference.of("validated", String.class, "d", false, s -> s.length() > 5);
        final var prefs = new Preferences();
        final var newPrefs = prefs.with(validated, "long_enough_string");
        Assert.assertEquals(newPrefs.get(validated), "long_enough_string");
    }

    @Test
    public void testValidationFailure() {
        final var validated = Preference.of("validated", String.class, "d", false, s -> s.length() > 5);
        final var prefs = new Preferences();
        Assert.assertThrows(IllegalArgumentException.class, () -> prefs.with(validated, "short"));
    }

    @Test
    public void testParameterValidationFailure() {
        final var validated = Preference.parameter("validated_param", String.class, false, s -> s.length() > 5);
        final var prefs = new Preferences();
        Assert.assertThrows(IllegalArgumentException.class, () -> prefs.with(validated, "short"));
    }

    @Test
    public void testRegister() {
        final var p1 = Preferences.register("reg1", String.class);
        final var p2 = Preferences.register("reg2", String.class, true);
        final var p3 = Preferences.register("reg3", String.class, "def", false);
        final var p4 = Preferences.register("reg4", String.class, "def");

        Assert.assertNotNull(p1);
        Assert.assertNotNull(p2);
        Assert.assertNotNull(p3);
        Assert.assertNotNull(p4);
        Assert.assertTrue(p2.readonly());
        Assert.assertEquals(p3.defaultValue(), "def");
    }

    @Test
    public void testKeys() {
        var prefs = new Preferences();
        final var p1 = Preference.of("p1", String.class, "d", false);
        prefs = prefs.with(p1, "v");
        final Set<Preference<?>> keys = prefs.keys();
        Assert.assertEquals(keys.size(), 1);
        Assert.assertTrue(keys.contains(p1));
    }

    @Test
    public void testToString() {
        var prefs = new Preferences();
        final var p1 = Preference.of("p1", String.class, "d", false);
        prefs = prefs.with(p1, "val");
        final var s = prefs.toString();
        Assert.assertTrue(s.contains("p1"));
        Assert.assertTrue(s.contains("val"));
    }

    @Test
    public void testToStringWithByteArray() {
        var prefs = new Preferences();
        final var p1 = Preference.of("bytes", byte[].class, new byte[0], false);
        final byte[] val = new byte[] { (byte) 0xCA, (byte) 0xFE };
        prefs = prefs.with(p1, val);
        final var s = prefs.toString();
        Assert.assertTrue(s.contains("cafe"));
    }
}
