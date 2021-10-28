package protocols.dhcp.option.codes.rebindingtimevalue;

import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;
import utils.date.DateArithmetic;

public class RebindingTimeValue extends DHCPOption {
    private Integer sec;

    public RebindingTimeValue(final Integer sec) {
        super(DHCPOptionCode.REBINDING_TIMEVALUE);
        this.sec = sec;
    }

    @Override
    public String toString() {
        return "Rebinding Time Value: (" + this.sec + ") " + DateArithmetic.toMinutes(this.sec) + " minutes";
    }

    public Integer getSec() {
        return sec;
    }
}
