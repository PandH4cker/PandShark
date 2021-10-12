package utils.net;

public final class IP {
    public static String fromHexString(final String hexString) {
        StringBuilder ip = new StringBuilder();
        for(int i = 0; i < hexString.length(); i = i + 2)
            ip.append(Integer.valueOf(hexString.substring(i, i + 2), 16)).append(
                    i + 2 >= hexString.length() ? "" : "."
            );
        return ip.toString();
    }
}
