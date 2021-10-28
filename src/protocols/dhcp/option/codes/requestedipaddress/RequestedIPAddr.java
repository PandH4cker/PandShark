package protocols.dhcp.option.codes.requestedipaddress;

import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;

public class RequestedIPAddr extends DHCPOption {
    private String ip;

    public RequestedIPAddr(final String ip) {
        super(DHCPOptionCode.RIPA);
        this.ip = ip;
    }

    @Override
    public String toString() {
        return "Requested IP Address: " + this.ip;
    }

    public String getIp() {
        return ip;
    }
}
