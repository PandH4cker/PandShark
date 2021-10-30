package utils.prompt;

import java.util.Scanner;

public final class Prompt {
    private static final Scanner scan = new Scanner(System.in);

    public static String prompt(final String message) {
        System.out.print(message);
        return scan.nextLine();
    }
}
