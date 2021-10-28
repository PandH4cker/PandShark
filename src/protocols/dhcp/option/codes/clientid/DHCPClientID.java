package protocols.dhcp.option.codes.clientid;

import protocols.arp.HardwareType;
import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;

public class DHCPClientID extends DHCPOption {
    private HardwareType hardwareType;
    private String MAC;

    public DHCPClientID(final HardwareType hardwareType, String MAC) {
        super(DHCPOptionCode.CLIENTID);
        this.hardwareType = hardwareType;
        this.MAC = MAC;
    }

    @Override
    public String toString() {
        return
                "Hardware Type: " + this.hardwareType + "\n" +
                "Client MAC Address: " + this.MAC;
    }

    public HardwareType getHardwareType() {
        return hardwareType;
    }

    public String getMAC() {
        return MAC;
    }
}
