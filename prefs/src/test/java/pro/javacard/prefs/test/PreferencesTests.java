package pro.javacard.prefs.test;

import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.prefs.Preference;
import pro.javacard.prefs.Preferences;

import java.util.Optional;

public class PreferencesTests {

    // Test preferences
    private static final Preference.Default<String> NAME = Preference.of("name", String.class, "default", false);
    private static final Preference.Default<String> READONLY_PREF = Preference.of("readonly", String.class, "readonly_default", true);

    @Test
    void testMergeWithReadonlyPreference() {
        Preferences prefs1 = new Preferences().with(READONLY_PREF, "existing");
        Preferences prefs2 = new Preferences().with(READONLY_PREF, "new_value");

        Preferences result = prefs1.merge(prefs2);

        Assert.assertEquals(result.get(READONLY_PREF), "existing");
    }

    @Test
    void testMergeReadonlyIntoEmpty() {
        Preferences empty = new Preferences();
        Preferences withReadonly = new Preferences().with(READONLY_PREF, "outcome");

        Preferences result = empty.merge(withReadonly);

        Assert.assertEquals(result.get(READONLY_PREF), "outcome");
    }

    @Test
    void testReadonlyPreferenceCreation() {
        Assert.assertTrue(READONLY_PREF.readonly());
        Assert.assertFalse(NAME.readonly());
    }

    @Test
    void testReadonlyPreferenceRemoval() {
        Preferences withReadonly = new Preferences().with(READONLY_PREF, "outcome");
        Assert.assertThrows(IllegalArgumentException.class, () -> {
            withReadonly.without(READONLY_PREF);
        });
    }


    @Test
    void testGetReturnsDefaultValues() {
        var pref1 = Preference.of("pref1", Boolean.class, false, false);
        var pref2 = Preference.of("pref2", Boolean.class, true, false);
        var prefs = new Preferences();

        Assert.assertTrue(prefs.get(pref2));
        Assert.assertFalse(prefs.get(pref1));
    }

    @Test
    void testValueOfReturnsEmptyForDefaults() {
        var pref1 = Preference.of("pref1", Boolean.class, false, false);
        var pref2 = Preference.of("pref2", Boolean.class, true, false);
        var prefs = new Preferences();

        Assert.assertEquals(Optional.empty(), prefs.valueOf(pref2));
        Assert.assertEquals(Optional.empty(), prefs.valueOf(pref1));
    }

    @Test
    void testWithOverridesValue() {
        var pref1 = Preference.of("pref1", Boolean.class, false, false);
        var prefs = new Preferences().with(pref1, true);

        Assert.assertTrue(prefs.get(pref1));
        Assert.assertEquals(Optional.of(Boolean.TRUE), prefs.valueOf(pref1));
    }

    @Test
    void testWithoutRemovesOverride() {
        var pref1 = Preference.of("pref1", Boolean.class, false, false);
        var pref2 = Preference.of("pref2", Boolean.class, true, false);
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
        var pref1 = Preference.of("pref1", Boolean.class, false, false);

        Assert.assertThrows(IllegalArgumentException.class, () -> new Preferences().with(pref1, null));
    }

    @Test
    void testParameterWithoutValue() {
        var param = Preference.parameter("optional-setting", String.class, false);
        var prefs = new Preferences();

        Assert.assertTrue(prefs.valueOf(param).isEmpty());
    }

    @Test
    void testParameterWithValue() {
        var param = Preference.parameter("optional-setting", String.class, false);
        var prefs = new Preferences().with(param, "configured-outcome");

        Assert.assertEquals(prefs.valueOf(param).get(), "configured-outcome");
        Assert.assertTrue(prefs.valueOf(param).isPresent());
    }

    @Test
    void testParameterCannotUseGet() {
        var param = Preference.parameter("optional-setting", String.class, false);
        var prefs = new Preferences().with(param, "outcome");

        // This should not compile - param is Parameter<String>, not Default<String>
        // prefs.get(param); // Compilation error - good!
    }

    @Test
    void testReadonlyParameter() {
        var param = Preference.parameter("readonly-param", String.class, true);
        var prefs1 = new Preferences().with(param, "initial");
        var prefs2 = new Preferences().with(param, "override");

        var merged = prefs1.merge(prefs2);

        Assert.assertEquals(merged.valueOf(param).get(), "initial");
        Assert.assertTrue(param.readonly());
    }

    @Test
    void testParameterWithNullValueThrows() {
        var param = Preference.parameter("param", String.class, false);

        Assert.assertThrows(IllegalArgumentException.class, () ->
                new Preferences().with(param, null));
    }

    @Test
    void testMixedDefaultsAndParameters() {
        var defaultPref = Preference.of("default", String.class, "default-outcome", false);
        var param = Preference.parameter("param", String.class, false);

        var prefs = new Preferences()
                .with(defaultPref, "overridden")
                .with(param, "param-outcome");

        Assert.assertEquals(prefs.get(defaultPref), "overridden");
        Assert.assertEquals(prefs.valueOf(param).get(), "param-outcome");
        Assert.assertEquals(prefs.size(), 2);
    }

}
