package core.headers.layer3;

import core.headers.layer3.ip.v4.exceptions.UnknownPort;

public enum EncapsulatedProtocol {
    ICMP(1, "ICMP"),
    IGMP(2, "IGMP"),
    TCP(6, "TCP"),
    UDP(17, "UDP");

    private Integer port;
    private String name;

    EncapsulatedProtocol(final Integer port, final String name) {
        this.port = port;
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public Integer getPort() {
        return port;
    }

    public static EncapsulatedProtocol fromPort(final Integer port) throws UnknownPort {
        for(EncapsulatedProtocol e : EncapsulatedProtocol.values())
            if (e.port.equals(port))
                return e;
        throw new UnknownPort("IPv4EncapsulatedProtocol ("+port+") unknown");
    }
}
