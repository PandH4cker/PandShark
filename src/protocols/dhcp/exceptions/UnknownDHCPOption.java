package protocols.dhcp.exceptions;

public class UnknownDHCPOption extends Exception {
    public UnknownDHCPOption(String errorMessage) {
        super(errorMessage);
    }
}
