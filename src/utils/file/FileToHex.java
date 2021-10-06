package utils.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public final class FileToHex {
    private static final String NEW_LINE = System.lineSeparator();
    private static final String UNKNOWN_CHARACTER = ".";

    public static String hexdump(String path) {
        File f = new File(path);
        if (!f.exists())
            throw new IllegalArgumentException("File not found! " + f.getPath());

        StringBuilder result = new StringBuilder();
        StringBuilder hex = new StringBuilder();
        StringBuilder input = new StringBuilder();

        int count = 0;
        int value;

        // path to inputstream....
        try (InputStream inputStream = new FileInputStream(f)) {

            while ((value = inputStream.read()) != -1) {

                hex.append(String.format("%02X", value));

                //If the character is unable to convert, just prints a dot "."
                if (!Character.isISOControl(value)) {
                    input.append((char) value);
                } else {
                    input.append(UNKNOWN_CHARACTER);
                }

                // After 15 bytes, reset everything for formatting purpose
                if (count == 14) {
                    result.append(String.format("%-60s | %s%n", hex, input));
                    hex.setLength(0);
                    input.setLength(0);
                    count = 0;
                } else {
                    count++;
                }

            }

            // if the count>0, meaning there is remaining content
            if (count > 0) {
                result.append(String.format("%-60s | %s%n", hex, input));
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return result.toString();
    }

    public static String fileToHexString(String path) {
        File f = new File(path);
        if (!f.exists())
            throw new IllegalArgumentException("File not found! " + f.getPath());

        StringBuilder hex = new StringBuilder();
        int value;

        // path to inputstream....
        try (InputStream inputStream = new FileInputStream(f)) {
            while ((value = inputStream.read()) != -1)
                hex.append(String.format("%02X", value));
        } catch (IOException e) {
            e.printStackTrace();
        }

        return hex.toString();
    }
}
