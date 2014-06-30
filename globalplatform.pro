-injars build
-injars lib/bcprov-jdk15on-150.jar(!META-INF/*)
-injars lib/jopt-simple-4.6.jar(!META-INF/*)
# JNA is library because we package everything back in
-libraryjars lib/jnasmartcardio.jar
-libraryjars  <java.home>/lib/rt.jar
-libraryjars  <java.home>/lib/jce.jar
-outjars optimized-globalplatform.jar
-dontobfuscate
-dontoptimize
-keep public class openkms.gp.GlobalPlatform {
    public <methods>;
}
-keep public class openkms.gp.** { public <methods>; public <fields>; }

-keep public class openkms.gp.GPTool {
    public static void main(java.lang.String[]);
}
# For enum-s (why this is not default?)
-keepclassmembers,allowoptimization enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
-printseeds
-dontnote
