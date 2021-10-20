package protocols.dhcp.exceptions;

public class UnknownFlagCode extends Exception {
    public UnknownFlagCode(String errorMessage) {
        super(errorMessage);
    }
}
