/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 * Copyright (C) 2015-2017 Martin Paljak, martin@martinpaljak.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package pro.javacard.gp;

import apdu4j.HexUtils;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Parses a CAP file as specified in JavaCard 2.2 VM Specification, chapter 6.
 */
public final class CAPFile {
    static final String[] componentNames = {"Header", "Directory", "Import", "Applet", "Class", "Method", "StaticField", "Export",
            "ConstantPool", "RefLocation", "Descriptor", "Debug"};
    private final HashMap<String, byte[]> capComponents = new HashMap<>();
    private final List<AID> appletAIDs = new ArrayList<>();
    private final List<byte[]> dapBlocks = new ArrayList<>();
    private final List<byte[]> loadTokens = new ArrayList<>();
    private final List<byte[]> installTokens = new ArrayList<>();
    private final List<CAPPackage> imports = new ArrayList<>();
    private String packageName = null;
    private AID packageAID = null;
    private byte flags = 0;
    private String cap_version = "unknown";
    private String package_version = "unknown";
    private Manifest manifest = null;

    public CAPFile(InputStream in) throws IOException {
        this(in, null);
    }

    private CAPFile(InputStream in, String packageName) throws IOException {
        ZipInputStream zip = new ZipInputStream(in);
        Map<String, byte[]> entries = getEntries(zip);
        if (packageName != null) {
            packageName = packageName.replace('.', '/') + "/javacard/";
        } else {
            Iterator<? extends String> it = entries.keySet().iterator();
            String lookFor = "Header.cap";
            while (it.hasNext()) {
                String s = it.next();
                if (s.endsWith(lookFor)) {
                    packageName = s.substring(0, s.lastIndexOf(lookFor));
                    break;
                }
            }
        }

        // Parse manifest
        byte[] mf = entries.remove("META-INF/MANIFEST.MF");
        if (mf != null) {
            ByteArrayInputStream mfi = new ByteArrayInputStream(mf);
            manifest = new Manifest(mfi);
        }

        // Avoid a possible NPE
        if (packageName == null) {
            throw new RuntimeException("Could not figure out the package name of the applet!");
        }

        this.packageName = packageName.substring(0, packageName.lastIndexOf("/javacard/")).replace('/', '.');
        for (String name : componentNames) {
            String fullName = packageName + name + ".cap";
            byte[] contents = entries.get(fullName);
            capComponents.put(name, contents);
        }
        // FIXME: Not existing and not used ZIP elements
        List<List<byte[]>> tables = new ArrayList<>();
        tables.add(dapBlocks);
        tables.add(loadTokens);
        tables.add(installTokens);
        String[] names = {"dap", "lt", "it"};
        for (int i = 0; i < names.length; i++) {
            int index = 0;
            while (true) {
                String fullName = "meta-inf/" + packageName.replace('/', '-') + names[i] + (index + 1);
                byte[] contents = entries.get(fullName);
                if (contents == null) {
                    break;
                }
                tables.get(i).add(contents);
                index++;
            }
        }
        zip.close();
        in.close();

        // Parse package.
        // See JCVM 2.2 spec section 6.3 for offsets.
        byte[] header = capComponents.get("Header");
        cap_version = String.format("%d.%d", header[8], header[7]);
        flags = header[9];
        package_version = String.format("%d.%d", header[11], header[10]);
        packageAID = new AID(header, 13, header[12]);

        // Parse applets
        // See JCVM 2.2 spec section 6.5 for offsets.
        byte[] applet = capComponents.get("Applet");
        if (applet != null) {
            int offset = 4;
            for (int j = 0; j < (applet[3] & 0xFF); j++) {
                int len = applet[offset++];
                appletAIDs.add(new AID(applet, offset, len));
                // Skip install_method_offset
                offset += len + 2;
            }
        }
        // Parse imports
        byte[] imps = capComponents.get("Import");
        if (imps != null) {
            int offset = 4;
            for (int j = 0; j < (imps[3] & 0xFF); j++) {
                CAPPackage p = new CAPPackage(new AID(imps, offset + 3, imps[offset + 2]), imps[offset + 1], imps[offset]);
                imports.add(p);
                offset += imps[offset + 2] + 3;
            }
        }
    }

    private Map<String, byte[]> getEntries(ZipInputStream in) throws IOException {
        Map<String, byte[]> result = new HashMap<>();
        while (true) {
            ZipEntry entry = in.getNextEntry();
            if (entry == null) {
                break;
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int c;
            while ((c = in.read(buf)) > 0) {
                bos.write(buf, 0, c);
            }
            result.put(entry.getName(), bos.toByteArray());
        }
        return result;
    }

    public AID getPackageAID() {
        return packageAID;
    }

    public List<AID> getAppletAIDs() {
        List<AID> result = new ArrayList<>();
        result.addAll(appletAIDs);
        return result;
    }

    public String getPackageName() {
        return packageName;
    }

    public int getCodeLength(boolean includeDebug) {
        int result = 0;
        for (String name : componentNames) {
            if (!includeDebug && (name.equals("Debug") || name.equals("Descriptor"))) {
                continue;
            }
            byte[] data = capComponents.get(name);
            if (data != null) {
                result += data.length;
            }
        }
        return result;
    }

    private byte[] createHeader(boolean includeDebug) {
        int len = getCodeLength(includeDebug);
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        // TODO: DAP blocks.
        bo.write((byte) 0xC4);
        // FIXME: usual length encoding.
        if (len < 0x80) {
            bo.write((byte) len);
        } else if (len <= 0xFF) {
            bo.write((byte) 0x81);
            bo.write((byte) len);
        } else if (len <= 0xFFFF) {
            bo.write((byte) 0x82);
            bo.write((byte) ((len & 0xFF00) >> 8));
            bo.write((byte) (len & 0xFF));
        } else {
            bo.write((byte) 0x83);
            bo.write((byte) ((len & 0xFF0000) >> 16));
            bo.write((byte) ((len & 0xFF00) >> 8));
            bo.write((byte) (len & 0xFF));
        }
        return bo.toByteArray();
    }

    public List<byte[]> getLoadBlocks(boolean includeDebug, boolean separateComponents, int blockSize) {
        List<byte[]> blocks = new ArrayList<byte[]>();

        if (!separateComponents) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            try {
                // TODO: DAP blocks.
                // See GP 2.1.1 Table 9-40
                bo.write(createHeader(includeDebug));
                bo.write(getRawCode(includeDebug));
            } catch (IOException ioe) {
                throw new RuntimeException(ioe);
            }
            blocks = GPUtils.splitArray(bo.toByteArray(), blockSize);
        } else {
            for (String name : componentNames) {
                if (!includeDebug && (name.equals("Debug") || name.equals("Descriptor"))) {
                    continue;
                }

                byte[] currentComponent = capComponents.get(name);
                if (currentComponent == null) {
                    continue;
                }
                if (name.equals("Header")) {
                    ByteArrayOutputStream bo = new ByteArrayOutputStream();
                    try {
                        bo.write(createHeader(includeDebug));
                        bo.write(currentComponent);
                    } catch (IOException ioe) {
                        throw new RuntimeException(ioe);
                    }
                    currentComponent = bo.toByteArray();
                }
                blocks = GPUtils.splitArray(currentComponent, blockSize);
            }
        }
        return blocks;
    }

    private byte[] getRawCode(boolean includeDebug) {
        byte[] result = new byte[getCodeLength(includeDebug)];
        int offset = 0;
        for (String name : componentNames) {
            if (!includeDebug && (name.equals("Debug") || name.equals("Descriptor"))) {
                continue;
            }
            byte[] currentComponent = capComponents.get(name);
            if (currentComponent == null) {
                continue;
            }
            System.arraycopy(currentComponent, 0, result, offset, currentComponent.length);
            offset += currentComponent.length;
        }
        return result;
    }

    public byte[] getLoadFileDataHash(String hash, boolean includeDebug) {
        try {
            return MessageDigest.getInstance(hash).digest(getRawCode(includeDebug));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Not possible", e);
        }
    }

    public void dump(PrintStream out) {
        out.println("CAP file (v" + cap_version + "), contains: " + String.join(", ", getFlags()) + " for JavaCard " + guessVersion());
        out.println("Package: " + packageName + " " + packageAID + " v" + package_version);
        for (CAPPackage imp : imports) {
            out.println("Import: " + imp.aid + String.format(" v%d.%d", imp.major, imp.minor));
        }
        for (AID applet : appletAIDs) {
            out.println("Applet: " + applet);
        }

        // Check manifest for metadata
        if (manifest != null) {
            Attributes mains = manifest.getMainAttributes();

            // iterate all packages
            Map<String, Attributes> ent = manifest.getEntries();
            if (ent.keySet().size() > 1) {
                throw new IllegalArgumentException("Too many elments in CAP");
            }
            Attributes caps = ent.get(ent.keySet().toArray()[0]);
            // Generic
            String jdk_name = mains.getValue("Created-By");
            // JC specific
            String cap_creation_time = caps.getValue("Java-Card-CAP-Creation-Time");
            String converter_version = caps.getValue("Java-Card-Converter-Version");
            String converter_provider = caps.getValue("Java-Card-Converter-Provider");

            out.println("Generated by " + converter_provider + " converter " + converter_version);
            out.println("On " + cap_creation_time + " with JDK " + jdk_name);
        }
        out.println("Total code size: " + getCodeLength(false) + " bytes (" + getCodeLength(true) + " with debug)");
        out.println("SHA256 (code): " + HexUtils.bin2hex(getLoadFileDataHash("SHA-256", false)));
        out.println("SHA1   (code): " + HexUtils.bin2hex(getLoadFileDataHash("SHA-1", false)));
    }

    private List<String> getFlags() {
        ArrayList<String> result = new ArrayList<>();
        // Table 6-3: CAP File Package Flags
        if ((flags & 0x01) == 0x01) {
            result.add("integers");
        }
        if ((flags & 0x02) == 0x02) {
            result.add("exports");
        }
        if ((flags & 0x04) == 0x04) {
            result.add("applets");
        }
        return result;
    }

    // Guess the targeted JavaCard version based on javacard.framework version
    // See https://stackoverflow.com/questions/25031338/how-to-get-javacard-version-on-card for a nice list
    public String guessVersion() {
        AID jf = new AID("A0000000620101");
        String result = "unknown";
        for (CAPPackage p : imports) {
            if (p.aid.equals(jf)) {
                if (p.minor == 0) {
                    return "2.1.1";
                } else if (p.minor == 2) {
                    return "2.2.1";
                } else if (p.minor == 3) {
                    return "2.2.2";
                } else if (p.minor == 4) {
                    return "3.0.1";
                } else if (p.minor == 5) {
                    return "3.0.4";
                } else {
                    return String.format("unknown: %d.%d", p.major, p.minor);
                }
            }
        }
        return result;
    }

    static class CAPPackage {
        AID aid;
        byte major;
        byte minor;

        CAPPackage(AID aid, byte major, byte minor) {
            this.aid = aid;
            this.major = major;
            this.minor = minor;
        }

        @Override
        public String toString() {
            return aid + String.format(" v%d.%d", major, minor);
        }
    }
}
