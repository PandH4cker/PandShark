package protocols.dhcp.option.codes.ipaddrleasetime;

import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;
import utils.date.DateArithmetic;

public class IPAddrLeaseTime extends DHCPOption {
    private Integer sec;

    public IPAddrLeaseTime(final Integer sec) {
        super(DHCPOptionCode.IPALT);
        this.sec = sec;
    }

    @Override
    public String toString() {
        return "IP Address Lease Time: (" + this.sec + ") " + DateArithmetic.toMinutes(this.sec) + " minutes";
    }

    public Integer getSec() {
        return sec;
    }
}
