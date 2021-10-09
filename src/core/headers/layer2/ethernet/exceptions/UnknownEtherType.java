package core.headers.layer2.ethernet.exceptions;

public class UnknownEtherType extends Exception {
    public UnknownEtherType(String errorMessage) {
        super(errorMessage);
    }
}
