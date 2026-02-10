package pro.javacard.gp.test;

import apdu4j.core.CommandAPDU;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.gp.GPSession;

import java.util.List;

public class TestStoreData {

    @Test
    public void testBuildStoreDataCommands() {
        byte[] a = {0x01, 0x02};
        byte[] b = {0x03, 0x04};
        byte[] c = {0x05, 0x06};

        List<CommandAPDU> cmds = GPSession.buildStoreDataCommands(List.of(a, b, c), 0x61);

        Assert.assertEquals(cmds.size(), 3);
        // Non-last blocks: P1 has b8 cleared (0x61 & 0x7F = 0x61)
        Assert.assertEquals(cmds.get(0).getP1(), 0x61);
        Assert.assertEquals(cmds.get(1).getP1(), 0x61);
        // Last block: P1 has b8 set (0x61 | 0x80 = 0xE1)
        Assert.assertEquals(cmds.get(2).getP1(), 0xE1);
        // P2 placeholder is 0 (core method replaces it with counter)
        for (CommandAPDU cmd : cmds) {
            Assert.assertEquals(cmd.getP2(), 0x00);
        }
        // CLA and INS
        for (CommandAPDU cmd : cmds) {
            Assert.assertEquals(cmd.getCLA() & 0xFF, 0x80);
            Assert.assertEquals(cmd.getINS() & 0xFF, 0xE2);
        }
        // Data preserved
        Assert.assertEquals(cmds.get(0).getData(), a);
        Assert.assertEquals(cmds.get(2).getData(), c);
    }

    @Test
    public void testSingleBlockGetsLastBlockBit() {
        byte[] data = {(byte) 0xAA};
        List<CommandAPDU> cmds = GPSession.buildStoreDataCommands(List.of(data), 0x10);

        Assert.assertEquals(cmds.size(), 1);
        // Single block is both first and last: P1 = 0x10 | 0x80 = 0x90
        Assert.assertEquals(cmds.get(0).getP1(), 0x90);
        Assert.assertEquals(cmds.get(0).getData(), data);
    }
}
