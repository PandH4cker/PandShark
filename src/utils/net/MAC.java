package utils.net;

import java.util.Arrays;

public final class MAC {
    public static String fromHexString(final String hexString) {
        return String.join(":", Arrays.asList(hexString.split("(?<=\\G.{2})")));
    }
}
