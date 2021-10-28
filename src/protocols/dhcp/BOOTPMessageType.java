package protocols.dhcp;

import protocols.dhcp.exceptions.UnknownMessageType;

public enum BOOTPMessageType {
    BOOTREQUEST(1, "Boot Request"),
    BOOTREPLY(2, "Boot Reply");

    private Integer op;
    private String name;

    BOOTPMessageType(final Integer op, final String name) {
        this.op = op;
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public Integer getOp() {
        return op;
    }

    public static BOOTPMessageType fromOp(final Integer op) throws UnknownMessageType {
        for(BOOTPMessageType messageType : BOOTPMessageType.values())
            if (messageType.op.equals(op))
                return messageType;
        throw new UnknownMessageType("DHCPMessageType ("+op+") unknown");
    }
}
