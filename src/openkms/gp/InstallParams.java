package openkms.gp;

/**
 * Installation parameters (will be in the format {@code 0xC9 00}
 *            (ie. no installation parameters) or {@code 0xC9 len data...}
 */
public class InstallParams {

    final private byte[] paramsBytes;

    public InstallParams(String hexParams) {
        byte[] bytes = hexStringToByteArray(hexParams);
        paramsBytes = new byte[bytes.length + 2];
        paramsBytes[0] = (byte)0xc9;
        paramsBytes[1] = (byte)bytes.length;
        System.arraycopy(bytes, 0, paramsBytes, 2, bytes.length);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public byte[] getParamsBytes() {
        return paramsBytes;
    }

}
