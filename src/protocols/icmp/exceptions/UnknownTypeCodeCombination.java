package protocols.icmp.exceptions;

public class UnknownTypeCodeCombination extends Exception {
    public UnknownTypeCodeCombination(String errorMessage) {
        super(errorMessage);
    }
}
