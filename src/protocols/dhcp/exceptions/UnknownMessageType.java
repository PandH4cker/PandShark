package protocols.dhcp.exceptions;

public class UnknownMessageType extends Exception {
    public UnknownMessageType(String errorMessage) {
        super(errorMessage);
    }
}
