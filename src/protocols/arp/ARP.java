package protocols.arp;

import core.headers.layer2.Layer2Protocol;
import core.headers.layer3.Layer3Protocol;
import protocols.PcapPacketData;

public class ARP extends PcapPacketData {
    private HardwareType hardwareType;
    private ProtocolType protocolType;
    private HardwareAddressLength hardwareAddressLength;
    private ProtocolAddressLength protocolAddressLength;


    public ARP(Integer id,
               Integer sequenceNumber,
               Layer2Protocol layer2Protocol,
               Layer3Protocol layer3Protocol) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol);
    }
}
