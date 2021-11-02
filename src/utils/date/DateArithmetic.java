package utils.date;

import java.util.Date;

public final class DateArithmetic {
    public static int toMinutes(int seconds) {
        return seconds / 60;
    }

    public static Date fromTimestamp(long timestamp) {
        return new Date(timestamp * 1000);
    }
}
