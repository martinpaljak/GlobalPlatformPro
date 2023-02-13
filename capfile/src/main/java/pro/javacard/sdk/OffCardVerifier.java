/*
 * Copyright (c) 2018-2022 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package pro.javacard.sdk;

import pro.javacard.capfile.CAPFile;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

public class OffCardVerifier {
    private final JavaCardSDK sdk;

    public static OffCardVerifier withSDK(JavaCardSDK sdk) {
        // Only main method in 2.1 SDK
        if (sdk.getVersion().isOneOf(SDKVersion.V211, SDKVersion.V212))
            throw new RuntimeException("Verification is supported with JavaCard SDK 2.2.1 or later");
        return new OffCardVerifier(sdk);
    }

    private OffCardVerifier(JavaCardSDK sdk) {
        this.sdk = sdk;
    }

    // Verify a CAP file against a specific JavaCard target SDK and a set of EXP files
    public void verifyAgainst(File f, JavaCardSDK target, Vector<File> exps) throws VerifierError, IOException {
        List<Path> exports = new ArrayList<>(exps.stream().map(File::toPath).collect(Collectors.toList()));
        exports.add(target.getExportDir());
        verify(f.toPath(), exports);
    }

    public void verifyAgainst(Path f, JavaCardSDK target, List<Path> exps) throws VerifierError, IOException {
        // Warn about recommended usage
        if (target.getVersion().isOneOf(SDKVersion.V304, SDKVersion.V305) && sdk.getVersion() != SDKVersion.V310) {
            System.err.println("NB! Please use JavaCard SDK 3.1.0 for verifying!");
        } else {
            if (!sdk.getRelease().equals("3.0.5u3")) {
                System.err.println("NB! Please use JavaCard SDK 3.0.5u3 or later for verifying!");
            }
        }
        List<Path> exports = new ArrayList<>(exps.stream().collect(Collectors.toList()));
        exports.add(target.getExportDir());
        verify(f, exports);
    }

    // Verify a given CAP file against a set of EXP files
    public void verify(Path f, List<Path> exps) throws VerifierError, IOException {
        Path tmp = Files.createTempDirectory("capfile");
        try (InputStream in = Files.newInputStream(f)) {
            CAPFile cap = CAPFile.fromStream(in);

            // Get verifier class
            Class<?> verifier = Class.forName("com.sun.javacard.offcardverifier.Verifier", true, sdk.getClassLoader());

            // Verifier takes a vector of files, so collect
            final Vector<File> expfiles = new Vector<>();
            for (Path e : exps) {
                // collect all export files to a list
                if (Files.isDirectory(e)) {
                    expfiles.addAll(Files.walk(e.toRealPath()).filter(p -> p.toString().endsWith(".exp")).map(Path::toFile).collect(Collectors.toList()));
                } else if (Files.isReadable(e)) {
                    if (e.toString().endsWith(".exp")) {
                        expfiles.add(e.toFile());
                    } else if (e.toString().endsWith(".jar")) {
                        expfiles.addAll(extractExps(e, tmp).stream().map(Path::toFile).collect(Collectors.toList()));
                    }
                }
            }

            String packagename = cap.getPackageName();

            try (FileInputStream input = new FileInputStream(f.toFile())) {
                // 3.0.5u1 still uses old signature
                if (sdk.getRelease().equals("3.0.5u3") || sdk.getRelease().equals("3.0.5u2") || sdk.getRelease().equals("3.1.0")) {
                    Method m = verifier.getMethod("verifyCap", File.class, String.class, Vector.class);
                    m.invoke(null, f.toFile(), packagename, expfiles);
                } else {
                    Method m = verifier.getMethod("verifyCap", FileInputStream.class, String.class, Vector.class);
                    m.invoke(null, input, packagename, expfiles);
                }
            } catch (InvocationTargetException e) {
                throw new VerifierError(e.getTargetException().getMessage(), e.getTargetException());
            }
        } catch (ReflectiveOperationException | IOException e) {
            throw new RuntimeException("Could not run verifier: " + e.getMessage());
        } finally {
            // Clean extracted exps
            rmminusrf(tmp);
        }
    }

    private static void rmminusrf(Path path) {
        try {
            Files.walk(path).sorted(Comparator.reverseOrder()).forEach(CAPFile::uncheckedDelete);
        } catch (FileNotFoundException | NoSuchFileException e) {
            // Already gone - do nothing.
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static Path under(Path out, String name) {
        Path p = out.resolve(name).normalize().toAbsolutePath();
        if (!p.startsWith(out))
            throw new IllegalArgumentException("Invalid path in JAR: " + p + " vs " + out);
        return p;
    }

    // Extracts .exp files from a jarfile to given path (temp folder) and returns the list of .exp files there
    public static List<Path> extractExps(Path jarfilePath, Path out) throws IOException {
        List<Path> exps = new ArrayList<>();
        try (JarFile jarfile = new JarFile(jarfilePath.toFile())) {
            Enumeration<JarEntry> entries = jarfile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().toLowerCase().endsWith(".exp")) {
                    Path f = under(out, entry.getName());
                    Path dir = f.getParent();
                    if (dir == null)
                        throw new IOException("Null parent"); // spotbugs
                    if (!Files.isDirectory(dir)) {
                        Files.createDirectories(dir);
                        //      throw new IOException("Failed to create folder: " + f.getParentFile());
                        // f = under(out, entry.getName());
                    }
                    try (InputStream is = jarfile.getInputStream(entry);
                         OutputStream fo = Files.newOutputStream(f)) {
                        byte[] buf = new byte[1024];
                        while (true) {
                            int r = is.read(buf);
                            if (r == -1) {
                                break;
                            }
                            fo.write(buf, 0, r);
                        }
                    }
                    exps.add(f);
                }
            }
        }
        return exps;
    }
}