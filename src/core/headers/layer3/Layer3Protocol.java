package core.headers.layer3;

public interface Layer3Protocol {
    EncapsulatedProtocol getProtocol();
    void setProtocol(EncapsulatedProtocol protocol);
}
