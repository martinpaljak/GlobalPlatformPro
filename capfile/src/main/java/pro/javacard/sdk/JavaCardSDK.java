/**
 * Copyright (c) 2015-2022 Martin Paljak
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package pro.javacard.sdk;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class JavaCardSDK {

    public static Optional<JavaCardSDK> detectSDK(Path path) {
        if (path == null)
            throw new NullPointerException("path is null");

        // Detect
        SDKVersion version = detectSDKVersion(path);

        if (version == null)
            return Optional.empty();

        Path exportDir = getExportDir(version);
        List<Path> apiJars = getApiJars(version);
        List<Path> compilerJars = getCompilerJars(version);
        List<Path> toolJars = getToolJars(version);

        JavaCardSDK sdk = new JavaCardSDK(path, version, exportDir, apiJars, toolJars, compilerJars);
        return Optional.of(sdk);
    }

    private static SDKVersion detectSDKVersion(Path root) {
        SDKVersion version = null;
        Path libDir = root.resolve("lib");
        if (Files.exists(libDir.resolve("tools.jar"))) {
            if (Files.exists(libDir.resolve("api_classic-3.1.0.jar")))
                return SDKVersion.V310;
            Path api = libDir.resolve("api_classic.jar");
            try (ZipFile apiZip = new ZipFile(api.toFile())) {
                if (apiZip.getEntry("javacard/framework/SensitiveArrays.class") != null) {
                    return SDKVersion.V305;
                }
                if (apiZip.getEntry("javacardx/framework/string/StringUtil.class") != null) {
                    return SDKVersion.V304;
                }
                return SDKVersion.V301;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else if (Files.exists(libDir.resolve("api21.jar"))) {
            version = SDKVersion.V212;
        } else if (Files.exists(root.resolve("bin").resolve("api.jar"))) {
            version = SDKVersion.V211;
        } else if (Files.exists(libDir.resolve("converter.jar"))) {
            // assume 2.2.1 first
            version = SDKVersion.V221;
            // test for 2.2.2 by testing api.jar
            Path api = libDir.resolve("api.jar");
            try (ZipFile apiZip = new ZipFile(api.toFile())) {
                ZipEntry testEntry = apiZip.getEntry("javacardx/apdu/ExtendedLength.class");
                if (testEntry != null) {
                    version = SDKVersion.V222;
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return version;
    }

    private final Path path;
    private final SDKVersion version;

    private final Path exportDir;
    private final List<Path> apiJars;
    private final List<Path> toolJars;
    private final List<Path> compilerJars;

    private JavaCardSDK(Path root, SDKVersion version, Path exportDir, List<Path> apiJars, List<Path> toolJars, List<Path> compilerJars) {
        this.path = root;
        this.version = version;

        this.exportDir = path.resolve(exportDir);
        this.apiJars = apiJars.stream().map(p -> path.resolve(p)).collect(Collectors.toList());
        this.compilerJars = compilerJars.stream().map(p -> path.resolve(p)).collect(Collectors.toList());
        this.toolJars = toolJars.stream().map(p -> path.resolve(p)).collect(Collectors.toList());
    }

    public Path getRoot() {
        return path;
    }

    public SDKVersion getVersion() {
        return version;
    }

    public List<Path> getApiJars() {
        return Collections.unmodifiableList(apiJars);
    }

    public List<Path> getCompilerJars() {
        return Collections.unmodifiableList(compilerJars);
    }

    public List<Path> getToolJars() {
        return Collections.unmodifiableList(toolJars);
    }

    public Path getExportDir() {
        return exportDir;
    }

    // This is for build and verification tools
    public JavaCardSDK target(SDKVersion targetVersion) {
        if (this.version == SDKVersion.V310 && targetVersion.isOneOf(SDKVersion.V304, SDKVersion.V305, SDKVersion.V310)) {
            List<Path> apiJars = new ArrayList<>();
            apiJars.add(Paths.get("lib", "api_classic-" + targetVersion.v + ".jar"));
            apiJars.add(Paths.get("lib", "api_classic_annotations-" + targetVersion.v + ".jar"));
            Path exportPath = Paths.get("api_export_files_" + targetVersion.v);
            return new JavaCardSDK(path, targetVersion, exportPath, apiJars, toolJars, compilerJars);
        } else {
            throw new IllegalStateException("Can not target " + targetVersion + " with " + this.version);
        }
    }

    // This indicates the highest class file version edible by SDK-s converter
    public static String getJavaVersion(SDKVersion version) {
        switch (version) {
            case V310:
                return "1.7";
            case V301:
            case V304:
            case V305:
                return "1.6";
            case V222:
                return "1.5";
            case V221:
                return "1.2";
            default:
                return "1.1";
        }
    }

    // Returns the classloader of verifier
    public ClassLoader getClassLoader() {
        return AccessController.doPrivileged(new PrivilegedAction<URLClassLoader>() {
            public URLClassLoader run() {
                try {
                    if (version.isV3()) {
                        return new URLClassLoader(new URL[]{path.resolve("lib").resolve("tools.jar").toUri().toURL()}, this.getClass().getClassLoader());
                    } else {
                        return new URLClassLoader(new URL[]{path.resolve("lib").resolve("offcardverifier.jar").toUri().toURL()}, this.getClass().getClassLoader());
                    }
                } catch (MalformedURLException e) {
                    throw new RuntimeException("Could not load classes: " + e.getMessage());
                }
            }
        });
    }

    public String getRelease() {
        if (version == SDKVersion.V305) {
            try {
                // Get verifier class
                Class<?> verifier = Class.forName("com.sun.javacard.offcardverifier.Verifier", false, getClassLoader());

                // Check if 3.0.5u3 (or, hopefully, later)
                try {
                    verifier.getDeclaredMethod("verifyTargetPlatform", String.class);
                    return "3.0.5u3";
                } catch (NoSuchMethodException e) {
                    // Do nothing
                }

                // Check if 3.0.5u1
                try {
                    verifier.getDeclaredMethod("verifyCap", FileInputStream.class, String.class, Vector.class);
                    return "3.0.5u1";
                } catch (NoSuchMethodException e) {
                    // Do nothing
                }
                // Assume 3.0.5u2 otherwise
                return "3.0.5u2";
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException("Could not figure out SDK release: " + e.getMessage());
            }
        } else {
            // No updates with older SDK-s
            return version.toString();
        }
    }

    public static Path getExportDir(SDKVersion version) {
        switch (version) {
            case V212:
                return Paths.get("api21_export_files");
            case V310:
                return Paths.get("api_export_files_3.1.0");
            default:
                return Paths.get("api_export_files");
        }
    }

    public static List<Path> getApiJars(SDKVersion version) {
        List<Path> jars = new ArrayList<>();
        switch (version) {
            case V211:
                jars.add(Paths.get("bin", "api.jar"));
                break;
            case V212:
                jars.add(Paths.get("lib", "api21.jar"));
                break;
            case V301:
            case V304:
            case V305:
                jars.add(Paths.get("lib", "api_classic.jar"));
                break;
            case V310:
                jars.add(Paths.get("lib", "api_classic-3.1.0.jar"));
                jars.add(Paths.get("lib", "api_classic_annotations-3.1.0.jar"));
                break;
            default:
                jars.add(Paths.get("lib", "api.jar"));
        }
        // Add annotations for 3.0.4 and 3.0.5
        if (version.isOneOf(SDKVersion.V304, SDKVersion.V305)) {
            jars.add(Paths.get("lib", "api_classic_annotations.jar"));
        }
        return jars;
    }

    public static List<Path> getToolJars(SDKVersion version) {
        List<Path> jars = new ArrayList<>();
        if (version.isOneOf(SDKVersion.V211)) {
            // We don't support verification with 2.1.X, so only converter
            jars.add(Paths.get("bin", "converter.jar"));
        } else if (version.isV3()) {
            jars.add(Paths.get("lib", "tools.jar"));
        } else {
            jars.add(Paths.get("lib", "converter.jar"));
            jars.add(Paths.get("lib", "offcardverifier.jar"));
        }
        return jars;
    }

    public static List<Path> getCompilerJars(SDKVersion version) {
        List<Path> jars = new ArrayList<>();
        if (version.isOneOf(SDKVersion.V304, SDKVersion.V305)) {
            jars.add(Paths.get("lib", "tools.jar"));
            jars.add(Paths.get("lib", "api_classic_annotations.jar"));
        } else if (version == SDKVersion.V310) {
            jars.add(Paths.get("lib", "tools.jar"));
            jars.add(Paths.get("lib", "api_classic_annotations-3.1.0.jar"));
        }
        return jars;
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof JavaCardSDK) {
            JavaCardSDK other = (JavaCardSDK) o;
            return path.toAbsolutePath().equals(other.path.toAbsolutePath()) && version.equals(other.version) && exportDir.equals(other.exportDir);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(path, exportDir);
    }
}
