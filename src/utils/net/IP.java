package utils.net;

import java.util.Arrays;
import java.util.stream.Collectors;

public final class IP {
    public static String v4FromHexString(final String hexString) {
        StringBuilder ip = new StringBuilder();
        for(int i = 0; i < hexString.length(); i = i + 2)
            ip.append(Integer.valueOf(hexString.substring(i, i + 2), 16)).append(
                    i + 2 >= hexString.length() ? "" : "."
            );
        return ip.toString();
    }

    public static String v6FromHexString(final String hexString) {
        return Arrays.stream(hexString
                .split("(?<=\\G.{4})"))
                .map(val -> val.replaceAll("^0+", ""))
                .collect(Collectors.joining(":"))
                .replaceAll("0000:", ":")
                .replaceAll(":{2,}", "::");
    }
}
