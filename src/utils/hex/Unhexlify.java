package utils.hex;

public final class Unhexlify {
    public static String unhexlify(String hexString) {
        int l = hexString.length();
        byte[] data = new byte[l / 2];
        for (int i = 0; i < l; i += 2) data[i / 2] =
                (byte) ((Character.digit(hexString.charAt(i), 16) << 4) +
                        Character.digit(hexString.charAt(i + 1), 16));
        return new String(data);
    }
}
