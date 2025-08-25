package pro.javacard.gp;

import apdu4j.core.HexUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestZeroLengthAID {

    @Test
    public void testZeroLengthLoadFileAID() throws Exception {
        // Test data with zero-length C4 tag (load file AID)
        // This simulates the issue reported in #392
        // E3 23 - Tag E3, length 23 (35 bytes)
        // 4F 08 A000000003000000 - Tag 4F (main AID), length 8
        // 9F70 01 01 - Tag 9F70 (lifecycle), length 1, data 01
        // C5 03 9EFE80 - Tag C5 (privileges), length 3
        // C4 00 - Tag C4 (load file AID), length 0 (this is the problem)
        // CE 02 0000 - Tag CE (version), length 2
        // CC 08 A000000003000000 - Tag CC (domain AID), length 8
        byte[] data = HexUtils.hex2bin("E3234F08A0000000030000009F700101C5039EFE80C400CE020000CC08A000000003000000");
        
        GPRegistry reg = new GPRegistry();
        
        // This should not throw an exception, but handle the zero-length AID gracefully
        reg.parse_and_populate(0x40, data, GPRegistryEntry.Kind.Application, GPCardProfile.defaultProfile());
        
        // Verify that the registry has the entry but without the invalid load file AID
        Assert.assertEquals(1, reg.allAIDs().size());
        GPRegistryEntry entry = reg.allEntries().iterator().next();
        Assert.assertFalse(entry.getLoadFile().isPresent());
    }

    @Test
    public void testZeroLengthMainAID() throws Exception {
        // Test data with zero-length 4F tag (main AID)
        // E3 11 - Tag E3, length 11 (17 bytes)
        // 4F 00 - Tag 4F (main AID), length 0 (this should cause entry to be skipped)
        // 9F70 01 01 - Tag 9F70 (lifecycle), length 1, data 01
        // C5 03 9EFE80 - Tag C5 (privileges), length 3
        // CE 02 0000 - Tag CE (version), length 2
        // CC 08 A000000003000000 - Tag CC (domain AID), length 8
        byte[] data = HexUtils.hex2bin("E3114F009F700101C5039EFE80CE020000CC08A000000003000000");
        
        GPRegistry reg = new GPRegistry();
        
        // This should not throw an exception, but skip the entry with invalid AID
        reg.parse_and_populate(0x40, data, GPRegistryEntry.Kind.Application, GPCardProfile.defaultProfile());
        
        // Verify that no entries were added due to invalid main AID
        Assert.assertEquals(0, reg.allAIDs().size());
    }

    @Test
    public void testZeroLengthModuleAID() throws Exception {
        // Test data with zero-length 84 tag (module AID)
        // E3 20 - Tag E3, length 20 (32 bytes)
        // 4F 08 A000000003000000 - Tag 4F (main AID), length 8
        // 9F70 01 01 - Tag 9F70 (lifecycle), length 1, data 01
        // C5 03 9EFE80 - Tag C5 (privileges), length 3
        // 84 00 - Tag 84 (module AID), length 0 (this should be skipped)
        // CE 02 0000 - Tag CE (version), length 2
        // CC 08 A000000003000000 - Tag CC (domain AID), length 8
        byte[] data = HexUtils.hex2bin("E3204F08A0000000030000009F700101C5039EFE808400CE020000CC08A000000003000000");
        
        GPRegistry reg = new GPRegistry();
        
        // This should not throw an exception, but handle the zero-length module AID gracefully
        reg.parse_and_populate(0x10, data, GPRegistryEntry.Kind.ExecutableLoadFile, GPCardProfile.defaultProfile());
        
        // Verify that the registry has the main entry but no modules
        Assert.assertEquals(1, reg.allAIDs().size());
        GPRegistryEntry entry = reg.allEntries().iterator().next();
        Assert.assertEquals(0, entry.getModules().size());
    }

    @Test
    public void testZeroLengthDomainAID() throws Exception {
        // Test data with zero-length CC tag (domain AID)
        // E3 15 - Tag E3, length 15 (21 bytes)  
        // 4F 08 A000000003000000 - Tag 4F (main AID), length 8
        // 9F70 01 01 - Tag 9F70 (lifecycle), length 1, data 01
        // C5 03 9EFE80 - Tag C5 (privileges), length 3
        // CE 02 0000 - Tag CE (version), length 2
        // CC 00 - Tag CC (domain AID), length 0 (this should be skipped)
        byte[] data = HexUtils.hex2bin("E3154F08A0000000030000009F700101C5039EFE80CE020000CC00");
        
        GPRegistry reg = new GPRegistry();
        
        // This should not throw an exception, but handle the zero-length domain AID gracefully
        reg.parse_and_populate(0x40, data, GPRegistryEntry.Kind.Application, GPCardProfile.defaultProfile());
        
        // Verify that the registry has the entry but without the invalid domain AID
        Assert.assertEquals(1, reg.allAIDs().size());
        GPRegistryEntry entry = reg.allEntries().iterator().next();
        Assert.assertFalse(entry.getDomain().isPresent());
    }
}