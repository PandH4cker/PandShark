package core.formats;

import core.headers.layer2.ethernet.EthernetHeader;
import core.headers.layer3.ip.v4.IPv4Header;
import core.headers.layer4.tcp.TCP;
import core.headers.layer4.udp.UDP;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;
import core.headers.pcap.PcapPacketHeader;
import protocols.PcapPacketData;
import protocols.arp.ARP;
import protocols.dhcp.DHCP;
import protocols.dhcp.option.DHCPOption;
import protocols.dns.DNS;
import protocols.dns.DNSType;
import protocols.dns.answer.DNSAnswer;
import protocols.dns.query.DNSQuery;
import protocols.ftp.FTP;
import protocols.icmp.ICMP;
import utils.bytes.Swapper;
import utils.hex.Hexlifier;
import utils.net.IP;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Predicate;

import static protocols.dns.DNSType.*;


public class Pcap {
    public static final String SWAPPED_HEX = "0xd4c3b2a1";
    public static int offset = 0;
    private static String magicNumber = "";

    private PcapGlobalHeader globalHeader;
    private LinkedHashMap<PcapPacketHeader, PcapPacketData> data;

    public Pcap(final PcapGlobalHeader globalHeader,
                final LinkedHashMap<PcapPacketHeader, PcapPacketData> data) {
        this.globalHeader = globalHeader;
        this.data = data;
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public LinkedHashMap<PcapPacketHeader, PcapPacketData> getData() {
        return data;
    }

    public static String read(int i, int bytesRead, String hexString) {
        StringBuilder hex = new StringBuilder();
        for(; i < offset + (bytesRead * 2); ++i) hex.append(hexString.charAt(i));
        offset = i;
        return magicNumber.isEmpty() ? "0x" + hex.toString().toLowerCase() :
                magicNumber.equals(SWAPPED_HEX) ? "0x" + Swapper.swappedHexString(hex.toString()) :
                        "0x" + hex;
    }

    public static String read(int i, int bytesRead, String hexString,
                              Predicate<LinkLayerHeader> llhPredicate, LinkLayerHeader llh) {
        StringBuilder hex = new StringBuilder();
        for(; i < offset + (bytesRead * 2); ++i) hex.append(hexString.charAt(i));
        offset = i;
        return llhPredicate.test(llh) ? "0x" + hex : "0x" + Swapper.swappedHexString(hex.toString());
    }

    public static Pcap fromHexString(String hexString) {
        LinkedHashMap<PcapPacketHeader, PcapPacketData> data = new LinkedHashMap<>();
        int indexOfPacket = 1;
        //Global Header
        magicNumber = read(offset, 4, hexString);
        PcapGlobalHeader pcapGlobalHeader = readPcapGlobalHeader(hexString);
        while (offset < hexString.length()) {
            //Packet Header
            ++indexOfPacket;
            PcapPacketHeader pcapPacketHeader = PcapPacketHeader.readPcapPacketHeader(hexString);
            handleGlobalHeaderNetwork(hexString, data, pcapGlobalHeader, pcapPacketHeader);
        }

        return new Pcap(pcapGlobalHeader, data);
    }

    private static void handleGlobalHeaderNetwork(String hexString, LinkedHashMap<PcapPacketHeader, PcapPacketData> data, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader pcapPacketHeader) {
        switch (pcapGlobalHeader.getuNetwork()) {
            case ETHERNET -> handleEthernet(hexString, data, pcapGlobalHeader, pcapPacketHeader);
            default -> {
                System.err.println("Data Link Type ("+ pcapGlobalHeader.getuNetwork()+") not implemented !");
                System.err.println("Skipping Packet Data...");
                offset += 2 * pcapPacketHeader.getuInclLen();
            }
        }
    }

    private static void handleEthernet(String hexString, LinkedHashMap<PcapPacketHeader, PcapPacketData> data, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader pcapPacketHeader) {
        EthernetHeader ethernetHeader = EthernetHeader.readEthernetHeader(hexString, pcapGlobalHeader);
        switch (ethernetHeader.getEtherType()) {
            case IPV4 -> handleIPv4(hexString, data, pcapGlobalHeader, pcapPacketHeader, ethernetHeader);
            case ARP -> handleARP(hexString, data, pcapGlobalHeader, pcapPacketHeader, ethernetHeader);
            default -> {
                System.err.println("Ether Type ("+ethernetHeader.getEtherType()+") not implemented !");
                System.err.println("Skipping Packet Data...");
                offset += 2 * (pcapPacketHeader.getuInclLen() - EthernetHeader.getSIZE());
            }
        }
    }

    private static void handleARP(String hexString, LinkedHashMap<PcapPacketHeader, PcapPacketData> data, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader pcapPacketHeader, EthernetHeader ethernetHeader) {
        ARP arp = ARP.readArp(hexString, pcapGlobalHeader, pcapPacketHeader, ethernetHeader);
        data.put(pcapPacketHeader, arp);
    }

    private static void handleIPv4(String hexString, LinkedHashMap<PcapPacketHeader, PcapPacketData> data, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader pcapPacketHeader, EthernetHeader ethernetHeader) {
        IPv4Header iPv4Header = IPv4Header.readiPv4Header(hexString, pcapGlobalHeader);
        switch (iPv4Header.getProtocol()) {
            case ICMP -> handleICMP(hexString, data, pcapGlobalHeader, pcapPacketHeader, ethernetHeader, iPv4Header);
            case UDP -> handleUDP(hexString, data, pcapGlobalHeader, pcapPacketHeader, ethernetHeader, iPv4Header);
            case TCP -> handleTCP(hexString, data, pcapGlobalHeader, pcapPacketHeader, ethernetHeader, iPv4Header);
            default -> {
                System.err.println("Encapsulated protocol ("+iPv4Header.getProtocol()+") not implemented !");
                System.err.println("Skipping Packet Data...");
                offset += 2 * (pcapPacketHeader.getuInclLen() - EthernetHeader.getSIZE() - IPv4Header.getSIZE());
            }
        }
    }

    private static void handleTCP(String hexString, LinkedHashMap<PcapPacketHeader, PcapPacketData> data, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader pcapPacketHeader, EthernetHeader ethernetHeader, IPv4Header iPv4Header) {
        TCP tcp = TCP.readTcp(hexString, pcapGlobalHeader);
        if (tcp.getOffset() > 5)
            tcp.setOption(read(offset, 8,
                    hexString, llh -> llh == LinkLayerHeader.ETHERNET,
                    pcapGlobalHeader.getuNetwork()));

        int remainingSize = pcapPacketHeader.getuInclLen() -
                EthernetHeader.getSIZE() -
                IPv4Header.getSIZE() -
                TCP.getSIZE() - (tcp.getOffset() > 5 ? 8 : 0);

        //TODO Detect the protocol

        if (remainingSize != 0 && (tcp.getSourcePort() == 21 || tcp.getDestinationPort() == 21))
            handleFTP(hexString, data, pcapGlobalHeader, pcapPacketHeader, ethernetHeader, iPv4Header, tcp, remainingSize);
        else
            offset += 2 * (pcapPacketHeader.getuInclLen() -
                    EthernetHeader.getSIZE() -
                    IPv4Header.getSIZE() -
                    TCP.getSIZE() - (tcp.getOffset() > 5 ? 8 : 0));
    }

    private static void handleFTP(String hexString, LinkedHashMap<PcapPacketHeader, PcapPacketData> data, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader pcapPacketHeader, EthernetHeader ethernetHeader, IPv4Header iPv4Header, TCP tcp, int size) {
        FTP ftp = FTP.readFtp(hexString, pcapGlobalHeader, ethernetHeader, iPv4Header, tcp, size);
        data.put(pcapPacketHeader, ftp);
    }

    private static void handleUDP(String hexString, LinkedHashMap<PcapPacketHeader, PcapPacketData> data, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader pcapPacketHeader, EthernetHeader ethernetHeader, IPv4Header iPv4Header) {
        UDP udp = UDP.readUdp(hexString, pcapGlobalHeader);
        //TODO Detect the protocol
        if (udp.getSourcePort() == 53 || udp.getDestinationPort() == 53)
            handleDNS(hexString, data, pcapGlobalHeader, pcapPacketHeader, ethernetHeader, iPv4Header);
        else if (udp.getSourcePort() == 68 || udp.getDestinationPort() == 68) {
            DHCP dhcp = DHCP.readDHCP(hexString, pcapGlobalHeader, ethernetHeader, iPv4Header);
            System.out.println("** DHCP Packet **");
            System.out.println("Message Type = " + dhcp.getMessageType());
            System.out.println("Hardware Type = " + dhcp.getHardwareType());
            System.out.println("Hardware Address Length = " + dhcp.getHardwareAddressLength());
            System.out.println("Hops = " + dhcp.getHops());
            System.out.println("Transaction ID = " + dhcp.getTransactionID());
            System.out.println("Second Elapsed = " + dhcp.getSecondsElapsed());
            System.out.println("BOOTP Flag = " + dhcp.getFlag());
            System.out.println("Client Address IP = " + dhcp.getClientIP());
            System.out.println("Your (client) Address IP = " + dhcp.getClientIP());
            System.out.println("Next server IP Address = " + dhcp.getNextServerIP());
            System.out.println("Relay agent IP Address = " + dhcp.getRelayAgentIP());
            System.out.println("Client MAC Address = " + dhcp.getClientMAC());
            System.out.println("Client Hardware Address Padding = " + dhcp.getClientHardwareAddressPadding());
            System.out.println("Server Host Name = " + dhcp.getServerHostname());
            System.out.println("Boot File Name = " + dhcp.getBootFilename());

            dhcp.readDHCPOptions(hexString, pcapGlobalHeader, pcapPacketHeader);
            for (DHCPOption option : dhcp.getOption())
                System.out.println(option);
        }
        else
            offset += 2 * (pcapPacketHeader.getuInclLen() -
                    EthernetHeader.getSIZE() -
                    IPv4Header.getSIZE() -
                    UDP.getSIZE());
    }

    private static void handleDNS(String hexString, LinkedHashMap<PcapPacketHeader, PcapPacketData> data, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader pcapPacketHeader, EthernetHeader ethernetHeader, IPv4Header iPv4Header) {
        DNS dns = DNS.readDns(hexString, pcapGlobalHeader, ethernetHeader, iPv4Header);
        List<DNSQuery> queries = new LinkedList<>();

        Integer offTracker = 0;
        for (int i = 0; i < dns.getQdCount(); ++i) {
            StringBuilder name = new StringBuilder();
            int nameLength;
            while((nameLength = Integer.decode(read(offset, 1, hexString,
                    llh -> llh == LinkLayerHeader.ETHERNET,
                    pcapGlobalHeader.getuNetwork()))) != 0) {
                ++offTracker;
                name.append(Hexlifier.unhexlify(read(offset, nameLength, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()))).append(".");
                offTracker += nameLength;
            }
            ++offTracker; // Null Byte
            name.setLength(name.length() - 1);
            Integer type = Integer.decode(read(offset, 2, hexString,
                    llh -> llh == LinkLayerHeader.ETHERNET,
                    pcapGlobalHeader.getuNetwork()));
            offTracker += 2;
            Integer dnsClass = Integer.decode(read(offset, 2, hexString,
                    llh -> llh == LinkLayerHeader.ETHERNET,
                    pcapGlobalHeader.getuNetwork()));
            offTracker += 2;

            DNSQuery query = new DNSQuery(name.toString(), type, dnsClass);
            queries.add(query);
        }
        dns.setQueries(queries);

        List<DNSAnswer> answers = new LinkedList<>();


        if (!(queries.get(0).getQueryType() == DNSType.NAPTR || queries.get(0).getQueryType() == null))
            for (int i = 0; i < dns.getAnCount(); ++i) {
                String ignoredC00c = read(offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork());
                offTracker += 2;
                String name = i == 0 ?
                        queries.get(0).getName() :
                        answers.get(i - 1).getType() == CNAME ?
                                answers.get(i - 1)
                                        .getData()
                                        .replace("CNAME: ", "") :
                                answers.get(i - 1).getName();
                Integer type = Integer.decode(read(offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()));
                offTracker += 2;
                Integer dnsClass = Integer.decode(read(offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()));
                offTracker += 2;
                Integer ttl = Integer.decode(read(offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()));
                offTracker += 4;
                Integer dataLength = Integer.decode(read(offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()));
                offTracker += 2;
                String answerData = read(offset, dataLength, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork());
                offTracker += dataLength;

                DNSAnswer answer = new DNSAnswer(name, type, dnsClass, ttl, dataLength, answerData);
                answer.setData(answer.getType() != null ? switch (answer.getType()) {
                    case HOSTADDR -> {
                        String ipv4 = IP.v4FromHexString(answer.getData().substring(2));
                        yield "Address: " + ipv4;
                    }
                    case IPV6ADDR -> {
                        String ipv6 = IP.v6FromHexString(answer.getData().substring(2));
                        yield "Address: " + ipv6;
                    }
                    case CNAME -> {
                        String cname = Hexlifier.unhexlify(answer.getData().substring(2));
                        yield "CNAME: " + answer.getName().replaceFirst("[^.]*", cname);
                    }
                    case NAMESERVER -> {
                        String nameServerPayload = answer.getData().substring(2);
                        int nameLength;
                        StringBuilder nameServer = new StringBuilder();
                        int index = 0;
                        while((nameLength = Integer.decode("0x" + nameServerPayload.substring(0, 2))) != 0) {
                            nameServerPayload = nameServerPayload.substring(2);
                            if (nameLength == Integer.decode("0xc0"))
                                yield "Name Server: " + answers.get(i - 1)
                                        .getData()
                                        .replace("Name Server: ", "")
                                        .replaceFirst("(([^.]+)\\.){1,"+index+"}", nameServer.toString());
                            nameServer.append(Hexlifier.unhexlify(nameServerPayload.substring(0, nameLength * 2)))
                                    .append(".");
                            ++index;
                            nameServerPayload = nameServerPayload.substring(nameLength * 2);
                        }
                        nameServer.setLength(nameServer.length() - 1);
                        yield "Name Server: " + nameServer;
                    }
                    case MAIL_EXCHANGE -> {
                        String mailExchangePayload = answer.getData().substring(2);

                        StringBuilder mailExchange = new StringBuilder();
                        Integer preference = Integer.decode("0x" + mailExchangePayload.substring(0, 4));
                        mailExchangePayload = mailExchangePayload.substring(4);

                        int nameLength;
                        while((nameLength = Integer.decode("0x" + mailExchangePayload.substring(0, 2))) != 0) {
                            mailExchangePayload = mailExchangePayload.substring(2);
                            if (nameLength == Integer.decode("0xc0"))
                                yield "Preference: " + preference +
                                      "\nMail Exchange: " + mailExchange + queries.get(0).getName();

                            mailExchange.append(Hexlifier.unhexlify(mailExchangePayload.substring(0, nameLength * 2)))
                                    .append(".");
                            mailExchangePayload = mailExchangePayload.substring(nameLength * 2);
                        }
                        mailExchange.setLength(mailExchange.length() - 1);
                        yield "Preference: " + preference +
                              "\nMail Exchange: " + mailExchange;
                    }
                    default -> answer.getData();
                } : answer.getData());

                answers.add(answer);
            }
        dns.setAnswers(answers);

        data.put(pcapPacketHeader, dns);
        System.out.println(dns);
        offset += 2 * (pcapPacketHeader.getuInclLen() - EthernetHeader.getSIZE() -
                IPv4Header.getSIZE() - UDP.getSIZE() - 12 - offTracker);
    }

    private static void handleICMP(String hexString, LinkedHashMap<PcapPacketHeader, PcapPacketData> data, PcapGlobalHeader pcapGlobalHeader, PcapPacketHeader pcapPacketHeader, EthernetHeader ethernetHeader, IPv4Header iPv4Header) {
        ICMP icmp = ICMP.readIcmp(hexString, pcapGlobalHeader, ethernetHeader, iPv4Header);
        data.put(pcapPacketHeader, icmp);
    }

    private static PcapGlobalHeader readPcapGlobalHeader(String hexString) {
        return new PcapGlobalHeader(
                magicNumber, Integer.decode(read(offset, 2, hexString)),
                Integer.decode(read(offset, 2, hexString)),
                Integer.decode(read(offset, 4, hexString)),
                Integer.decode(read(offset, 4, hexString)),
                Integer.decode(read(offset, 4, hexString)),
                Integer.decode(read(offset, 4, hexString))
        );
    }

}
