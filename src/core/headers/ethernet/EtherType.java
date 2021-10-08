package core.headers.ethernet;

public enum EtherType {
    DEC("6000", "DEC"),
    DEC2("0609", "DEC"),
    XNS("0600", "XNS"),
    IPV4("0800", "IPv4"),
    ARP("0806", "ARP"),
    DOMAIN("8019", "Domain"),
    RARP("8035", "RARP"),
    AppleTalk("809B", "AppleTalk"),
    IEEE802_1Q("8100", "802.1Q"),
    IPV6("86DD", "IPv6");

    private String name;
    private String codeType;

    EtherType(final String codeType, final String name) {
        this.codeType = codeType;
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name;
    }

    public static EtherType fromCodeType(final String codeType) throws UnknownEtherType {
        for(EtherType e : EtherType.values())
            if (e.codeType.equals(codeType))
                return e;
        throw new UnknownEtherType("EtherType ("+codeType+") unknown");
    }
}
