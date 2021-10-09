package utils.bytes;

public final class Bytefier {
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static byte getBit(byte b, int position) {
        return (byte) ((b >> position) & 1);
    }

    public static byte getFourthLowest(byte b) {
        return (byte) (b & 0x0F);
    }

    public static byte getFourthHighest(byte b) {
        return (byte) (b >> 4);
    }

    public static byte setByteAt(byte b, int position) {
        return (byte) (b | 1L << position);
    }

    public static byte clearByteAt(byte b, int position) {
        return (byte) (b & ~(1L << position));
    }
}
