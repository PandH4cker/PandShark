package protocols.arp;

import protocols.arp.exceptions.UnknownProtocolAddressLength;

public enum ProtocolAddressLength {
    IPV4(4, "IPv4"),
    IPV6(16, "IPv6");

    private Integer length;
    private String name;

    ProtocolAddressLength(final Integer length, final String name) {
        this.length = length;
        this.name = name;
    }

    public Integer getLength() {
        return length;
    }

    @Override
    public String toString() {
        return name;
    }

    public static ProtocolAddressLength fromLength(final Integer length) throws UnknownProtocolAddressLength {
        for(ProtocolAddressLength pal : ProtocolAddressLength.values())
            if (pal.length.equals(length))
                return pal;
        throw new UnknownProtocolAddressLength("ProtocolAddressLength ("+length+") unknown");
    }
}
