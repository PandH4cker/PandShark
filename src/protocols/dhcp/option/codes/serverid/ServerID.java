package protocols.dhcp.option.codes.serverid;

import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;

public class ServerID extends DHCPOption {
    private String ip;

    public ServerID(final String ip) {
        super(DHCPOptionCode.SERVERID);
        this.ip = ip;
    }

    @Override
    public String toString() {
        return "DHCP Server Identifier: " + this.ip;
    }

    public String getIp() {
        return ip;
    }
}
