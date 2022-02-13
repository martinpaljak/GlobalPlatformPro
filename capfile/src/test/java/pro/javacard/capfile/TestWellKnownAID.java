package pro.javacard.capfile;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.InputStream;
import java.util.Optional;

public class TestWellKnownAID {

    @Test
    public void testInternalList() throws Exception {
        try (InputStream in = WellKnownAID.class.getResourceAsStream("aid_list.yml")) {
            System.out.println(in);
            WellKnownAID.load(in);
            Assert.assertEquals(WellKnownAID.getName(AID.fromString("D276000085494A434F5058")), Optional.of("com.nxp.id.jcopx"));
        }
    }
}
