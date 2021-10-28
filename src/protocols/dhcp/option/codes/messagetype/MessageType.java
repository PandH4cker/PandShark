package protocols.dhcp.option.codes.messagetype;

import protocols.dhcp.exceptions.UnknownMessageType;

public enum MessageType {
    DHCPDISCOVER(1, "Discover"),
    DHCPOFFER(2, "Offer"),
    DHCPREQUEST(3, "Request"),
    DHCPDECLINE(4, "Decline"),
    DHCPACK(5, "Ack"),
    DHCPNAK(6, "Nak"),
    DHCPRELEASE(7, "Release");

    private Integer value;
    private String messageType;

    MessageType(final Integer value, final String messageType) {
        this.value = value;
        this.messageType = messageType;
    }

    public Integer getValue() {
        return value;
    }

    @Override
    public String toString() {
        return messageType;
    }

    public static MessageType fromValue(final Integer value) throws UnknownMessageType {
        for(MessageType msg : MessageType.values())
            if (msg.value.equals(value))
                return msg;
        throw new UnknownMessageType("MessageType ("+value+") unknown");
    }
}
