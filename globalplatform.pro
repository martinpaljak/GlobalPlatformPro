-libraryjars  <java.home>/lib/rt.jar
-libraryjars  <java.home>/lib/jce.jar

-injars target/gp.jar
-keep public class pro.javacard.gp.GPTool {
    public static void main(java.lang.String[]);
}


-outjars gp.jar
-dontobfuscate

# For enum-s (why this is not default?)
-keepclassmembers class * extends java.lang.Enum {
    <fields>;
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-printseeds seeds.txt
-dontnote !pro.javacard.**
-dontwarn !pro.javacard.**

# From apdu4j
-keep public class * extends java.security.Provider {*;}
-keep class com.sun.jna.** { *; }
-keep class jnasmartcardio.** { *; }

-keep class org.slf4j.impl.Simple** { *; }

# Fix for java.lang.ClassFormatError: LVTT entry for 'X' in class file Z does not match any LVT entry
-optimizations !code/allocation/variable