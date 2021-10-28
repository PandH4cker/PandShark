package protocols.dhcp.option.codes.renewtimevalue;

import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;
import utils.date.DateArithmetic;

public class RenewTimeValue extends DHCPOption {
    private Integer sec;

    public RenewTimeValue(final Integer sec) {
        super(DHCPOptionCode.RENEW_TIMEVALUE);
        this.sec = sec;
    }

    @Override
    public String toString() {
        return "Renewal Time Value: (" + this.sec + ") " + DateArithmetic.toMinutes(this.sec) + " minutes";
    }

    public Integer getSec() {
        return sec;
    }
}
