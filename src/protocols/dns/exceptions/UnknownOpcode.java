package protocols.dns.exceptions;

public class UnknownOpcode extends Exception {
    public UnknownOpcode(String errorMessage) {
        super(errorMessage);
    }
}
