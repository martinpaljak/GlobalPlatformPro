package openkms.gp;

/**
 * Installation parameters (will be in the format {@code 0xC9 00}
 *            (ie. no installation parameters) or {@code 0xC9 len data...}
 */
public class InstallParams {

    final private byte[] paramsBytes;

    public InstallParams(String hexParams) {
        byte[] bytes = GPUtils.stringToByteArray(hexParams);
        paramsBytes = new byte[bytes.length + 2];
        paramsBytes[0] = (byte)0xc9;
        paramsBytes[1] = (byte)bytes.length;
        System.arraycopy(bytes, 0, paramsBytes, 2, bytes.length);
    }

    public byte[] getParamsBytes() {
        return paramsBytes;
    }

}
