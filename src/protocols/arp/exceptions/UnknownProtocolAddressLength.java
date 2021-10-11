package protocols.arp.exceptions;

public class UnknownProtocolAddressLength extends Exception {
    public UnknownProtocolAddressLength(String errorMessage) {
        super(errorMessage);
    }
}
