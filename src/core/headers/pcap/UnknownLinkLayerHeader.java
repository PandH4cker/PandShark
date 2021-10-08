package core.headers.pcap;

public class UnknownLinkLayerHeader extends Exception {
    public UnknownLinkLayerHeader(String errorMessage) {
        super(errorMessage);
    }
}
