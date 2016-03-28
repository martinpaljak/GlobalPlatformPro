-injars build
-injars lib/bcprov-jdk15on-154.jar(!META-INF/**)
-injars lib/jopt-simple-4.9.jar(!META-INF/**)
-injars lib/slf4j-api-1.7.13.jar(!META-INF/**)
-dontwarn org.slf4j.**
# these are library because we package everything back in
-libraryjars lib/slf4j-simple-1.7.13.jar
-libraryjars lib/apdu4j-pcsc.jar
-libraryjars  <java.home>/lib/rt.jar
-libraryjars  <java.home>/lib/jce.jar
-outjars optimized-globalplatform.jar
-dontobfuscate
-dontoptimize
-keep public class pro.javacard.gp.GlobalPlatform {
    public <methods>;
}
-keep public class pro.javacard.gp.** { public <methods>; public <fields>; }

-keep public class pro.javacard.gp.GPTool {
    public static void main(java.lang.String[]);
}
# For enum-s (why this is not default?)
-keepclassmembers,allowoptimization enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
-printseeds
-dontnote
