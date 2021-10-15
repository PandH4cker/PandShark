package protocols.dns.exceptions;

public class UnknownQueryClass extends Exception {
    public UnknownQueryClass(String errorMessage) {
        super(errorMessage);
    }
}
