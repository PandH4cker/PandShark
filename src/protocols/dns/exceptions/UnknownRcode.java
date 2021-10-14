package protocols.dns.exceptions;

public class UnknownRcode extends Exception {
    public UnknownRcode(String errorMessage) {
        super(errorMessage);
    }
}
