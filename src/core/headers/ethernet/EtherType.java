package core.headers.ethernet;

public enum EtherType {
    DEC("0x6000", "DEC"),
    DEC2("0x0609", "DEC"),
    XNS("0x0600", "XNS"),
    IPV4("0x0800", "IPv4"),
    ARP("0x0806", "ARP"),
    DOMAIN("0x8019", "Domain"),
    RARP("0x8035", "RARP"),
    AppleTalk("0x809B", "AppleTalk"),
    IEEE802_1Q("0x8100", "802.1Q"),
    IPV6("0x86DD", "IPv6");

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

    public String getCodeType() {
        return codeType;
    }

    public static EtherType fromCodeType(final String codeType) throws UnknownEtherType {
        for(EtherType e : EtherType.values())
            if (e.codeType.equals(codeType))
                return e;
        throw new UnknownEtherType("EtherType ("+codeType+") unknown");
    }
}
