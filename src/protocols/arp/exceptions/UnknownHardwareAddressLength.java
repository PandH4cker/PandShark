package protocols.arp.exceptions;

public class UnknownHardwareAddressLength extends Exception {
    public UnknownHardwareAddressLength(String errorMessage) {
        super(errorMessage);
    }
}
