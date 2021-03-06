package pro.javacard.gp;

import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.i.CardKeysProvider;

import java.util.Optional;

public class TestPlaintextKeysProvider {

    @Test
    public void testGarbage() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Assert.assertFalse(p.getCardKeys("404142434445464748494a4b4c4d4e4fXX").isPresent());
    }

    @Test
    public void testMasterKey() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Assert.assertTrue(p.getCardKeys("404142434445464748494a4b4c4d4e4f").isPresent());
    }

    @Test
    public void testDiversification() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Optional<GPCardKeys> pk = p.getCardKeys("emv:404142434445464748494a4b4c4d4e4f");
        Assert.assertTrue(pk.isPresent());
    }

    @Test
    public void testUnknownDiversification() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Optional<GPCardKeys> pk = p.getCardKeys("foobar:404142434445464748494a4b4c4d4e4f");
        Assert.assertFalse(pk.isPresent());
    }

    @Test
    public void testDefaultKeys() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Optional<GPCardKeys> pk = p.getCardKeys("default");
        Assert.assertTrue(pk.isPresent());
    }

    @Test
    public void testDefaultKeysWithDiversifier() {
        CardKeysProvider p = new PlaintextKeysProvider();
        Optional<GPCardKeys> pk = p.getCardKeys("kdf3:default");
        Assert.assertTrue(pk.isPresent());
    }
}
