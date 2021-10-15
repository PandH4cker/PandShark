package protocols.dns.exceptions;

public class UnknownQueryType extends Exception {
    public UnknownQueryType(String errorMessage) {
        super(errorMessage);
    }
}
