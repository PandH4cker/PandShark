package utils.bytes;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class Swapper {
    public static Byte[] reverseBytes(Byte[] bytes) {
        List<Byte> byteList = Arrays.asList(bytes);
        Collections.reverse(byteList);
        return byteList.toArray(new Byte[0]);
    }

    public static String swappedHexString(String hexString) {
        List<String> splittedHexString = Arrays.asList(hexString.split("(?<=\\G.{2})"));
        Collections.reverse(splittedHexString);
        return String.join("", splittedHexString);
    }
}
