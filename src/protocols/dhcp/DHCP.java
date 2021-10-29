package protocols.dhcp;

import core.formats.Pcap;
import core.headers.layer2.Layer2Protocol;
import core.headers.layer2.ethernet.EthernetHeader;
import core.headers.layer3.Layer3Protocol;
import core.headers.layer3.ip.v4.IPv4Header;
import core.headers.layer4.udp.UDP;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;
import core.headers.pcap.PcapPacketHeader;
import protocols.PcapPacketData;
import protocols.arp.HardwareType;
import protocols.arp.exceptions.UnknownHardwareType;
import protocols.dhcp.exceptions.UnknownDHCPOption;
import protocols.dhcp.exceptions.UnknownFlagCode;
import protocols.dhcp.exceptions.UnknownMessageType;
import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;
import protocols.dhcp.option.codes.clientid.DHCPClientID;
import protocols.dhcp.option.codes.end.End;
import protocols.dhcp.option.codes.ipaddrleasetime.IPAddrLeaseTime;
import protocols.dhcp.option.codes.messagetype.DHCPMessageType;
import protocols.dhcp.option.codes.messagetype.MessageType;
import protocols.dhcp.option.codes.paramrequestitem.ParamRequestList;
import protocols.dhcp.option.codes.rebindingtimevalue.RebindingTimeValue;
import protocols.dhcp.option.codes.renewtimevalue.RenewTimeValue;
import protocols.dhcp.option.codes.requestedipaddress.RequestedIPAddr;
import protocols.dhcp.option.codes.serverid.ServerID;
import protocols.dhcp.option.codes.subnetmask.SubnetMask;
import utils.hex.Hexlifier;
import utils.net.IP;
import utils.net.MAC;

import java.util.LinkedList;
import java.util.List;

public class DHCP extends PcapPacketData {
    private static final Integer SIZE = 240;

    private BOOTPMessageType messageType;
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
    private List<DHCPOption> options;
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
            this.messageType = BOOTPMessageType.fromOp(messageType);
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

    @Override
    public String toString() {
        return
                "Message Type = "  + this.messageType  + "\n" +
                "Hardware Type = " + this.hardwareType + "\n" +
                "Hardware Address Length = " + this.hardwareAddressLength + "\n" +
                "Hops = " + this.hops + "\n" +
                "Transaction ID = " + this.transactionID + "\n" +
                "Second Elapsed = " + this.secondsElapsed + "\n" +
                "BOOTP Flag = " + this.flag + "\n" +
                "Client Address IP = " + this.clientIP + "\n" +
                "Your (client) Address IP = " + this.futureClientIP + "\n" +
                "Next server IP Address = " + this.nextServerIP + "\n" +
                "Relay agent IP Address = " + this.relayAgentIP + "\n" +
                "Client MAC Address = " + this.clientMAC + "\n" +
                "Client Hardware Address Padding = " + this.clientHardwareAddressPadding + "\n" +
                "Server Host Name = " + this.serverHostname + "\n" +
                "Boot File Name = " + this.bootFilename;
    }

    public void readDHCPOptions(String hexString, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader packetHeader) {
        int needToBeRead = packetHeader.getuInclLen() - EthernetHeader.getSIZE() - IPv4Header.getSIZE() -
                               UDP.getSIZE() - DHCP.getSIZE();
        String optionsAndPadding = Pcap.read(Pcap.offset, needToBeRead, hexString,
                                                llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())
                                   .substring(2);

        int i = 0;
        boolean endReached = false;
        List<DHCPOption> dhcpOptions = new LinkedList<>();

        while (!endReached) {
            int code = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
            i += 2;
            DHCPOptionCode optionCode = null;
            try {
                optionCode = DHCPOptionCode.fromCode(code);
            } catch (UnknownDHCPOption ignored) {}

            DHCPOption option = null;
            switch (optionCode) {
                case DHCP_MESSAGETYPE -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    int value = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;
                    try {
                        MessageType messageType = MessageType.fromValue(value);
                        dhcpOptions.add(new DHCPMessageType(messageType));
                    } catch (UnknownMessageType ignored) {}
                }
                case SUBNET_MASK -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    dhcpOptions.add(new SubnetMask(IP.v4FromHexString(optionsAndPadding.substring(i, i + 8))));
                    i += 8;
                }
                case RENEW_TIMEVALUE -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    dhcpOptions.add(new RenewTimeValue(Integer.parseInt(optionsAndPadding.substring(i, i + 8), 16)));
                    i += 8;
                }
                case REBINDING_TIMEVALUE -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    dhcpOptions.add(new RebindingTimeValue(Integer.parseInt(optionsAndPadding.substring(i, i + 8), 16)));
                    i += 8;
                }
                case IPALT -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    dhcpOptions.add(new IPAddrLeaseTime(Integer.parseInt(optionsAndPadding.substring(i, i + 8), 16)));
                    i += 8;
                }
                case SERVERID -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    dhcpOptions.add(new ServerID(IP.v4FromHexString(optionsAndPadding.substring(i, i + 8))));
                    i += 8;
                }
                case CLIENTID -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    int hardwareCode = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    HardwareType hardwareType = null;
                    try {
                        hardwareType = HardwareType.fromCode(hardwareCode);
                    } catch (UnknownHardwareType e) {}

                    String MACAddress = MAC.fromHexString(optionsAndPadding.substring(i, i + 12));
                    i += 12;

                    dhcpOptions.add(new DHCPClientID(hardwareType, MACAddress));
                }
                case RIPA -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    dhcpOptions.add(new RequestedIPAddr(IP.v4FromHexString(optionsAndPadding.substring(i, i + 8))));
                    i += 8;
                }
                case PARAM_REQUEST_LIST -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;

                    List<DHCPOptionCode> paramRequestItemList = new LinkedList<>();
                    for (int item = 0; item < length; ++item) {
                        int paramValue = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                        i += 2;
                        try {
                            DHCPOptionCode dhcpOptionCode = DHCPOptionCode.fromCode(paramValue);
                            paramRequestItemList.add(dhcpOptionCode);
                        } catch (UnknownDHCPOption ignored) {}
                    }

                    dhcpOptions.add(new ParamRequestList(paramRequestItemList));
                }

                case END -> {
                    dhcpOptions.add(new End());
                    endReached = true;
                }
                default -> {
                    int length = Integer.parseInt(optionsAndPadding.substring(i, i + 2), 16);
                    i += 2;
                    i += length * 2;
                }
            }
        }
        this.options = dhcpOptions;
        this.padding = optionsAndPadding.substring(i);
    }

    public static DHCP readDHCP(String hexString,
                                PcapGlobalHeader pcapGlobalHeader,
                                EthernetHeader ethernetHeader,
                                IPv4Header iPv4Header) {
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
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 6, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 10, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 64, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 128, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                iPv4Header.getIdentification(),
                null,
                ethernetHeader,
                iPv4Header
        );
    }

    public static Integer getSIZE() {
        return SIZE;
    }

    public BOOTPMessageType getMessageType() {
        return messageType;
    }

    public void setMessageType(BOOTPMessageType messageType) {
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
        return options;
    }

    public void setOption(List<DHCPOption> options) {
        this.options = options;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }
}
