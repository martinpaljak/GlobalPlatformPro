package pro.javacard.gptool;

import org.bouncycastle.util.encoders.Hex;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestAPDUParser {

    @Test
    public void testCBOR() throws Exception {
        final var a = "00220000 {pin: false}";
        final byte[] apdu = APDUParsers.stringToAPDU(a);
        // NOTE: Jackson 2.20.x started generating fixed length, yay! Was: 0022000007bf6370696ef4ff
        Assert.assertEquals(Hex.decode("0022000006a16370696ef4"), apdu);
    }

    @Test
    public void testLength() throws Exception {
        final var a = "00220000 11223344";
        final byte[] apdu = APDUParsers.stringToAPDU(a);
        Assert.assertEquals(Hex.decode("002200000411223344"), apdu);
    }

    @Test
    public void testLengthExtra() throws Exception {
        final var a = "00220000    11:22:33:44";
        final byte[] apdu = APDUParsers.stringToAPDU(a);
        Assert.assertEquals(Hex.decode("002200000411223344"), apdu);
    }

    @Test
    public void test0x() throws Exception {
        final var a = "00220000  0x04  0x11: 0X22  33\n440x00";
        final byte[] apdu = APDUParsers.stringToAPDU(a);
        Assert.assertEquals(Hex.decode("00220000041122334400"), apdu);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testSimple() {
        final var a = "00220000  05  11:22:33:44";
        final byte[] apdu = APDUParsers.stringToAPDU(a);
        System.out.println(Hex.toHexString(apdu));
    }

    @Test
    public void testShowCBOR() {
        System.out.println(APDUParsers.visualize_structure(Hex.decode("bf6474657374f4ff")));
    }

}
