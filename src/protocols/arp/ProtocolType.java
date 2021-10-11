package protocols.arp;

import protocols.arp.exceptions.UnknownProtocolType;

public enum ProtocolType {
    IP("0x0800", "IP");

    private String codeType;
    private String name;

    ProtocolType(final String codeType, final String name) {
        this.codeType = codeType;
        this.name = name;
    }

    public String getCodeType() {
        return codeType;
    }

    @Override
    public String toString() {
        return name;
    }

    public static ProtocolType fromCodeType(final String codeType) throws UnknownProtocolType {
        for(ProtocolType pt : ProtocolType.values())
            if (pt.codeType.equals(codeType))
                return pt;
        throw new UnknownProtocolType("ProtocolType ("+codeType+") unknown");
    }
}
