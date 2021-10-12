package utils.integers;

public final class Intify {
    public static int fromByteArray(byte[] bytes) {
        int val = 0;
        if(bytes.length > 4) throw new RuntimeException("Too big to fit in int");
        for (int i = 0; i < bytes.length; i++) {
            val=val<<8;
            val=val|(bytes[i] & 0xFF);
        }
        return val;
    }
}
