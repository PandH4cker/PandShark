package protocols.dhcp.option.codes.messagetype;

import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;

public class DHCPMessageType extends DHCPOption {
    private MessageType messageType;

    public DHCPMessageType(final MessageType messageType) {
        super(DHCPOptionCode.DHCP_MESSAGETYPE);
        this.messageType = messageType;
    }

    @Override
    public String toString() {
        return "DHCP: " + this.messageType + " (" + this.messageType.getValue() + ")";
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public void setMessageType(MessageType messageType) {
        this.messageType = messageType;
    }
}
