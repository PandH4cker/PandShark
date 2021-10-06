package protocols.icmp;

public class UnknownTypeCodeCombination extends Exception {
    public UnknownTypeCodeCombination(String errorMessage) {
        super(errorMessage);
    }
}
