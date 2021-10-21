package protocols.dhcp;

import core.formats.Pcap;
import core.headers.layer2.Layer2Protocol;
import core.headers.layer2.ethernet.EthernetHeader;
import core.headers.layer3.Layer3Protocol;
import core.headers.layer3.ip.v4.IPv4Header;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;
import protocols.PcapPacketData;
import protocols.arp.HardwareType;
import protocols.arp.exceptions.UnknownHardwareType;
import protocols.dhcp.exceptions.UnknownFlagCode;
import protocols.dhcp.exceptions.UnknownMessageType;
import protocols.dhcp.option.DHCPOption;
import utils.hex.Hexlifier;
import utils.net.IP;
import utils.net.MAC;

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


    public DHCP(final Integer messageType,
                final Integer hardwareType,
                final Integer hardwareAddressLength,
                final Integer hops,
                final String transactionID,
                final Integer secondsElapsed,
                final String flags,
                final String clientIP,
                final String futureClientIP,
                final String nextServerIP,
                final String relayAgentIP,
                final String clientMAC,
                final String clientHardwareAddressPadding,
                final String serverHostname,
                final String bootFilename,
                final String magicCookie,
                final Integer id,
                final Long sequenceNumber,
                final Layer2Protocol layer2Protocol,
                final Layer3Protocol layer3Protocol) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol);
        try {
            this.messageType = DHCPMessageType.fromOp(messageType);
        } catch (UnknownMessageType e) {
            this.messageType = null;
        }
        try {
            this.hardwareType = HardwareType.fromCode(hardwareType);
        } catch (UnknownHardwareType e) {
            this.hardwareType = null;
        }
        this.hardwareAddressLength = hardwareAddressLength;
        this.hops = hops;
        this.transactionID = transactionID;
        this.secondsElapsed = secondsElapsed;
        try {
            this.flag = BOOTPFlag.fromCode(Integer.parseInt(String.valueOf(flags.charAt(0))));
        } catch (UnknownFlagCode e) {
            this.flag = null;
        }
        this.reserved = flags.substring(1);
        this.clientIP = IP.v4FromHexString(clientIP);
        this.futureClientIP = IP.v4FromHexString(futureClientIP);
        this.nextServerIP = IP.v4FromHexString(nextServerIP);
        this.relayAgentIP = IP.v4FromHexString(relayAgentIP);
        this.clientMAC = MAC.fromHexString(clientMAC);
        this.clientHardwareAddressPadding = clientHardwareAddressPadding;
        this.serverHostname = Hexlifier.unhexlify(serverHostname);
        this.bootFilename = Hexlifier.unhexlify(bootFilename);
        this.magicCookie = Hexlifier.unhexlify(magicCookie);
    }

    public static DHCP readDHCP(String hexString, PcapGlobalHeader pcapGlobalHeader, EthernetHeader ethernetHeader, IPv4Header iPv4Header) {
        return new DHCP(
                Integer.decode(Pcap.read(Pcap.offset, 1, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())),
                Integer.decode(Pcap.read(Pcap.offset, 1, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())),
                Integer.decode(Pcap.read(Pcap.offset, 1, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())),
                Integer.decode(Pcap.read(Pcap.offset, 1, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Integer.decode(Pcap.read(Pcap.offset, 2, hexString,
                    llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())),
                Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Pcap.read(Pcap.offset, 6, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Pcap.read(Pcap.offset, 10, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Pcap.read(Pcap.offset, 64, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Pcap.read(Pcap.offset, 128, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()),
                iPv4Header.getIdentification(),
                null,
                ethernetHeader,
                iPv4Header
        );
    }

    public DHCPMessageType getMessageType() {
        return messageType;
    }

    public void setMessageType(DHCPMessageType messageType) {
        this.messageType = messageType;
    }

    public HardwareType getHardwareType() {
        return hardwareType;
    }

    public void setHardwareType(HardwareType hardwareType) {
        this.hardwareType = hardwareType;
    }

    public Integer getHardwareAddressLength() {
        return hardwareAddressLength;
    }

    public void setHardwareAddressLength(Integer hardwareAddressLength) {
        this.hardwareAddressLength = hardwareAddressLength;
    }

    public Integer getHops() {
        return hops;
    }

    public void setHops(Integer hops) {
        this.hops = hops;
    }

    public String getTransactionID() {
        return transactionID;
    }

    public void setTransactionID(String transactionID) {
        this.transactionID = transactionID;
    }

    public Integer getSecondsElapsed() {
        return secondsElapsed;
    }

    public void setSecondsElapsed(Integer secondsElapsed) {
        this.secondsElapsed = secondsElapsed;
    }

    public BOOTPFlag getFlag() {
        return flag;
    }

    public void setFlag(BOOTPFlag flag) {
        this.flag = flag;
    }

    public String getReserved() {
        return reserved;
    }

    public void setReserved(String reserved) {
        this.reserved = reserved;
    }

    public String getClientIP() {
        return clientIP;
    }

    public void setClientIP(String clientIP) {
        this.clientIP = clientIP;
    }

    public String getFutureClientIP() {
        return futureClientIP;
    }

    public void setFutureClientIP(String futureClientIP) {
        this.futureClientIP = futureClientIP;
    }

    public String getNextServerIP() {
        return nextServerIP;
    }

    public void setNextServerIP(String nextServerIP) {
        this.nextServerIP = nextServerIP;
    }

    public String getRelayAgentIP() {
        return relayAgentIP;
    }

    public void setRelayAgentIP(String relayAgentIP) {
        this.relayAgentIP = relayAgentIP;
    }

    public String getClientMAC() {
        return clientMAC;
    }

    public void setClientMAC(String clientMAC) {
        this.clientMAC = clientMAC;
    }

    public String getClientHardwareAddressPadding() {
        return clientHardwareAddressPadding;
    }

    public void setClientHardwareAddressPadding(String clientHardwareAddressPadding) {
        this.clientHardwareAddressPadding = clientHardwareAddressPadding;
    }

    public String getServerHostname() {
        return serverHostname;
    }

    public void setServerHostname(String serverHostname) {
        this.serverHostname = serverHostname;
    }

    public String getBootFilename() {
        return bootFilename;
    }

    public void setBootFilename(String bootFilename) {
        this.bootFilename = bootFilename;
    }

    public String getMagicCookie() {
        return magicCookie;
    }

    public void setMagicCookie(String magicCookie) {
        this.magicCookie = magicCookie;
    }

    public List<DHCPOption> getOption() {
        return option;
    }

    public void setOption(List<DHCPOption> option) {
        this.option = option;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }
}
