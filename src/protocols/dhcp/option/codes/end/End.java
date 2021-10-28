package protocols.dhcp.option.codes.end;

import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;

public class End extends DHCPOption {
    public End() {
        super(DHCPOptionCode.END);
    }

    @Override
    public String toString() {
        return "Option End: 255";
    }
}
