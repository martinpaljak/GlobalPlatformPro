package pro.javacard.gp;

import apdu4j.HexUtils;
import org.junit.Test;
import pro.javacard.gp.SEAccessControl;

public class TestSEAC {

    @Test
    public void testGoogleExtensions() throws Exception {
        byte[] d = HexUtils.stringToBin("FF401AE218E116C114 a90d0190bfc879dbe161a3df66b6352c68b85c18");

        SEAccessControl.AcrListResponse resp = SEAccessControl.AcrListResponse.fromBytes(d);
        SEAccessControl.printList(resp.acrList);
    }
}