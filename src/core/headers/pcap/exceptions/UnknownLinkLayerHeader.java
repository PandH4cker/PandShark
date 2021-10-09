package core.headers.pcap.exceptions;

public class UnknownLinkLayerHeader extends Exception {
    public UnknownLinkLayerHeader(String errorMessage) {
        super(errorMessage);
    }
}
