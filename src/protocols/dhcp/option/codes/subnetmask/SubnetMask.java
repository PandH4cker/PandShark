package protocols.dhcp.option.codes.subnetmask;

import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;

public class SubnetMask extends DHCPOption {
    private String maskIp;

    public SubnetMask(final String maskIp) {
        super(DHCPOptionCode.SUBNET_MASK);
        this.maskIp = maskIp;
    }

    @Override
    public String toString() {
        return "Subnet Mask: " + this.maskIp;
    }

    public String getMaskIp() {
        return maskIp;
    }
}
