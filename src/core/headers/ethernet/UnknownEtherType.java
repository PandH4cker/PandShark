package core.headers.ethernet;

public class UnknownEtherType extends Exception {
    public UnknownEtherType(String errorMessage) {
        super(errorMessage);
    }
}
