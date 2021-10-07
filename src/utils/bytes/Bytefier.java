package utils.bytes;

public final class Bytefier {
    public static Byte[] hexStringToBytearray(String hexString) {
        Byte[] bytes = new Byte[hexString.length() / 2];
        for(int i = 0; i < bytes.length; ++i) {
            int index = i * 2;
            int j = Integer.parseInt(hexString.substring(index, index + 2), 16);
            bytes[i] = (byte) j;
        }
        return bytes;
    }
}
