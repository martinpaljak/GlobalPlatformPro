package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestIssue392Fix {

    @Test
    public void testZeroLengthLoadFileAIDHandling() throws Exception {
        // Test data with zero-length C4 tag (load file AID) as reported in issue #392
        // E3 23 - Tag E3, length 23 (35 bytes)
        // 4F 08 A000000003000000 - Tag 4F (main AID), length 8
        // 9F70 01 01 - Tag 9F70 (lifecycle), length 1, data 01
        // C5 03 9EFE80 - Tag C5 (privileges), length 3
        // C4 00 - Tag C4 (load file AID), length 0 (this would cause IllegalArgumentException)
        // CE 02 0000 - Tag CE (version), length 2
        // CC 08 A000000003000000 - Tag CC (domain AID), length 8
        byte[] data = HexUtils.hex2bin("E3234F08A0000000030000009F700101C5039EFE80C400CE020000CC08A000000003000000");
        
        GPRegistry reg = new GPRegistry();
        
        // This should not throw IllegalArgumentException: "AID must be between 5 and 16 bytes: 0"
        // Instead it should gracefully handle the zero-length AID and continue parsing
        reg.parse_and_populate(0x40, data, GPRegistryEntry.Kind.Application, GPCardProfile.defaultProfile());
        
        // Verify that the registry has the entry (the parsing succeeded)
        Assert.assertEquals(1, reg.allAIDs().size());
        GPRegistryEntry entry = reg.iterator().next();
        
        // Verify main properties are set correctly
        Assert.assertEquals("A000000003000000", entry.getAID().toString());
        Assert.assertEquals(1, entry.getLifeCycle());
        
        // Verify the zero-length load file AID was handled gracefully (no source set)
        Assert.assertFalse(entry.getSource().isPresent());
    }
}