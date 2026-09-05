// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp.ng;

import apdu4j.apdulette.Chef;
import apdu4j.core.HexUtils;
import apdu4j.core.MockBIBO;
import org.testng.annotations.Test;
import pro.javacard.capfile.AID;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVs;
import pro.javacard.tlv.Tag;

import java.util.EnumSet;

import static org.testng.Assert.*;

// Test INSTALL [for registry update] (GPC 2.4 11.5.2.3.5, Table 11-46), P1=0x40
public class TestRegistryUpdate {

    private static final AID INSTANCE = new AID("A000000151535041");
    private static final AID CREL = new AID("A00000015143525300");

    @Test
    public void testRegistryUpdateWithCrelNotify() {
        // Build the same contactless parameters the CLI produces for --cl-notify
        var params = GPToolNG.install_params(GPCommandLineInterface.parser.parse(new String[] { "--cl-notify", CREL.toString() }));

        // Expected command data field per Table 11-46:
        // 00 (SD AID len) | 00 (data len) | 08 + instance AID | 00 (priv len) |
        // <params len> + params | 00 (token len)
        var expectedData = HexUtils.bin2hex(new byte[] { 0x00, 0x00 })
                + "08" + INSTANCE.toString()
                + "00"
                + HexUtils.bin2hex(new byte[] { (byte) params.length }) + HexUtils.bin2hex(params)
                + "00";
        // INS=E6, P1=40 (for registry update), P2=00, Le=00
        var expectedApdu = "80E64000" + HexUtils.bin2hex(new byte[] { (byte) (expectedData.length() / 2) }) + expectedData + "00";

        var mock = MockBIBO.with(expectedApdu, "9000");
        var chef = Chef.of(mock);
        var response = chef.cook(GlobalPlatformCookbook.install_for_registry_update(
                INSTANCE, EnumSet.noneOf(GPRegistryEntryNG.Privilege.class), params));
        assertEquals(response.getSW(), 0x9000);

        // The Registry Update Parameters carry an A3 "Add to the CREL List" with the notify AID
        assertEquals(TLVs.parse(params).find(0xEF, 0xA1, 0xA3, 0x4F).orElseThrow().value(), CREL.getBytes());
    }

    @Test
    public void testRegistryUpdateRawParams() {
        var params = HexUtils.hex2bin("C90100");
        var expectedData = "0000" + "08" + INSTANCE.toString() + "00" + "03" + "C90100" + "00";
        var expectedApdu = "80E64000" + HexUtils.bin2hex(new byte[] { (byte) (expectedData.length() / 2) }) + expectedData + "00";

        var mock = MockBIBO.with(expectedApdu, "9000");
        var chef = Chef.of(mock);
        var response = chef.cook(GlobalPlatformCookbook.install_for_registry_update(
                INSTANCE, EnumSet.noneOf(GPRegistryEntryNG.Privilege.class), params));
        assertEquals(response.getSW(), 0x9000);
    }

    // build_install_data is the defensive net: a pre-formed EF-only blob (no C9) must get an
    // empty C9 prepended as a sibling, never have the EF nested inside C9.
    @Test
    public void testBuildInstallDataKeepsEfSibling() {
        var pkg = new AID("0102030405");
        var app = new AID("A00000015100");
        var ef = HexUtils.hex2bin("EF07A005A5038201C0"); // EF { A0 { A5 { 82 01 C0 } } }
        var data = GlobalPlatformCookbook.build_install_data(pkg, app, app,
                EnumSet.noneOf(GPRegistryEntryNG.Privilege.class), ef);
        // The trailing install-parameters field is length 0B = C9 00 followed by the un-nested EF
        assertTrue(HexUtils.bin2hex(data).endsWith("0BC900EF07A005A5038201C0"));
    }

    @Test
    public void testRegistryUpdateWithPrivileges() {
        var privs = EnumSet.of(GPRegistryEntryNG.Privilege.CardLock);
        var params = new byte[0];
        // priv field is 3 bytes; params length 00; token length 00
        var mock = MockBIBO.of("9000");
        var chef = Chef.of(mock);
        var response = chef.cook(GlobalPlatformCookbook.install_for_registry_update(INSTANCE, privs, params));
        assertEquals(response.getSW(), 0x9000);
    }

    // INSTALL [for load] with no hash, no params and no DM token must still carry the
    // mandatory Load Token length (GPC 2.4 Table 11-42) - the data ends with 00 00 00
    // (hash-len, param-len, token-len), matching legacy gp.
    @Test
    public void testInstallForLoadTokenLength() {
        var pkg = new AID("0102030405");
        var isd = new AID("A000000151000000");
        var expectedData = "05" + pkg + "08" + isd + "00" + "00" + "00";
        var expectedApdu = "80E60200" + HexUtils.bin2hex(new byte[] { (byte) (expectedData.length() / 2) }) + expectedData + "00";

        var mock = MockBIBO.with(expectedApdu, "9000");
        var chef = Chef.of(mock);
        var response = chef.cook(GlobalPlatformCookbook.install_for_load(pkg, isd, new byte[0], new byte[0]));
        assertEquals(response.getSW(), 0x9000);
    }

    // DELETE carries its token under tag 9E and must NOT get a spurious trailing 00.
    @Test
    public void testDeleteNoTrailingToken() {
        var aid = new AID("0102030405");
        var data = TLV.of(Tag.ber(0x4F), aid.getBytes()).encode();
        var expectedApdu = "80E40000" + HexUtils.bin2hex(new byte[] { (byte) data.length }) + HexUtils.bin2hex(data) + "00";

        var mock = MockBIBO.with(expectedApdu, "9000");
        var chef = Chef.of(mock);
        var response = chef.cook(GlobalPlatformCookbook.delete_aid(aid, false));
        assertEquals(response.getSW(), 0x9000);
    }
}
