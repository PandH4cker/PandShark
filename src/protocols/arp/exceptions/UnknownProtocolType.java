package protocols.arp.exceptions;

public class UnknownProtocolType extends Exception {
    public UnknownProtocolType(String errorMessage) {
        super(errorMessage);
    }
}
