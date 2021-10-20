package protocols.dhcp;

import core.headers.layer2.Layer2Protocol;
import core.headers.layer3.Layer3Protocol;
import protocols.PcapPacketData;
import protocols.arp.HardwareType;
import protocols.dhcp.option.DHCPOption;

import java.util.List;

public class DHCP extends PcapPacketData {
    private DHCPMessageType messageType;
    private HardwareType hardwareType;
    private Integer hardwareAddressLength;
    private Integer hops;
    private String transactionID;
    private Integer secondsElapsed;
    private BOOTPFlag flag;
    private String reserved;
    private String clientIP;
    private String futureClientIP;
    private String nextServerIP;
    private String relayAgentIP;
    private String clientMAC;
    private String clientHardwareAddressPadding;
    private String serverHostname;
    private String bootFilename;
    private String magicCookie;
    private List<DHCPOption> option;
    private String padding;



    public DHCP(Integer id, Long sequenceNumber, Layer2Protocol layer2Protocol, Layer3Protocol layer3Protocol) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol);
    }
}
