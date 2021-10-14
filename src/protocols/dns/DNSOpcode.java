package protocols.dns;

import protocols.dns.exceptions.UnknownOpcode;

public enum DNSOpcode {
    QUERY(0, "Standard Query"),
    IQUERY(1, "Reversed Query"),
    STATUS(2, "Status");

    private Integer code;
    private String name;

    DNSOpcode(final Integer code, final String name) {
        this.code = code;
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public static DNSOpcode fromCode(final Integer code) throws UnknownOpcode {
        for(DNSOpcode opcode : DNSOpcode.values())
            if (opcode.code.equals(code))
                return opcode;
        throw new UnknownOpcode("UnknownOpcode ("+code+") unknown");
    }
}
