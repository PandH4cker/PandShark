package protocols.arp.exceptions;

public class UnknownHardwareType extends Exception {
    public UnknownHardwareType(String errorMessage) {
        super(errorMessage);
    }
}
