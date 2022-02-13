package pro.javacard.sdk;

import org.testng.SkipException;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

public class TestSDKs {

    static boolean interactive() {
        return System.getProperty("java.class.path").contains("idea_rt.jar");
    }

    @Test
    public void testDetection() throws Exception {
        if (!interactive())
            throw new SkipException("Not interactive");
        Stream<Path> dirs = Files.list(Paths.get("/Users/martin/projects/oracle_javacard_sdks"));
        dirs.forEach(dir -> {
            System.out.println("Folder: " + dir + ": " + JavaCardSDK.detectSDK(dir).map(sdk -> sdk.getRelease()).orElse("not SDK"));
        });
    }
}
