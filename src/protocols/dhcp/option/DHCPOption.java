package protocols.dhcp.option;

public abstract class DHCPOption {
    private DHCPOptionCode code;

    public DHCPOption(final DHCPOptionCode code) {
        this.code = code;
    }

    public DHCPOptionCode getCode() {
        return code;
    }

    public void setCode(DHCPOptionCode code) {
        this.code = code;
    }
}
