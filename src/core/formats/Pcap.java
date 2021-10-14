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
import protocols.icmp.ICMP;
import utils.bytes.Swapper;

import java.util.LinkedHashMap;
import java.util.function.Predicate;


public class Pcap {
    private static final String SWAPPED_HEX = "0xd4c3b2a1";
    private static int offset;
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

    private static String read(int i, int bytesRead, String hexString) {
        StringBuilder hex = new StringBuilder();
        for(; i < offset + (bytesRead * 2); ++i) hex.append(hexString.charAt(i));
        offset = i;
        return magicNumber.isEmpty() ? "0x" + hex.toString().toLowerCase() :
                magicNumber.equals(SWAPPED_HEX) ? "0x" + Swapper.swappedHexString(hex.toString()) :
                        "0x" + hex;
    }

    private static String read(int i, int bytesRead, String hexString,
                               Predicate<LinkLayerHeader> llhPredicate, LinkLayerHeader llh) {
        StringBuilder hex = new StringBuilder();
        for(; i < offset + (bytesRead * 2); ++i) hex.append(hexString.charAt(i));
        offset = i;
        return llhPredicate.test(llh) ? "0x" + hex : "0x" + Swapper.swappedHexString(hex.toString());
    }

    public static Pcap fromHexString(String hexString) {
        LinkedHashMap<PcapPacketHeader, PcapPacketData> data = new LinkedHashMap<>();

        //Global Header
        magicNumber = read(offset, 4, hexString);
        PcapGlobalHeader pcapGlobalHeader = new PcapGlobalHeader(
                magicNumber, Integer.decode(read(offset, 2, hexString)),
                Integer.decode(read(offset, 2, hexString)),
                Integer.decode(read(offset, 4, hexString)),
                Integer.decode(read(offset, 4, hexString)),
                Integer.decode(read(offset, 4, hexString)),
                Integer.decode(read(offset, 4, hexString))
        );
        while (offset < hexString.length()) {
            //Packet Header
            PcapPacketHeader pcapPacketHeader = new PcapPacketHeader(
                    Integer.decode(read(offset, 4, hexString)),
                    Integer.decode(read(offset, 4, hexString)),
                    Integer.decode(read(offset, 4, hexString)),
                    Integer.decode(read(offset, 4, hexString))
            );
            switch (pcapGlobalHeader.getuNetwork()) {
                case ETHERNET -> {
                    EthernetHeader ethernetHeader = new EthernetHeader(
                            read(offset, 6, hexString,
                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                    pcapGlobalHeader.getuNetwork()).substring(2),
                            read(offset, 6, hexString,
                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                    pcapGlobalHeader.getuNetwork()).substring(2),
                            read(offset, 2, hexString,
                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                    pcapGlobalHeader.getuNetwork())
                    );

                    switch (ethernetHeader.getEtherType()) {
                        case IPV4 -> {
                            IPv4Header iPv4Header = new IPv4Header(
                                    read(offset, 1, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork()).substring(2),
                                    read(offset, 1, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork()),
                                    Integer.decode(read(offset, 2, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork())),
                                    Integer.decode(read(offset, 2, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork())),
                                    read(offset, 2, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork()).substring(2),
                                    Integer.decode(read(offset, 1, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork())),
                                    Integer.decode(read(offset, 1, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork())),
                                    read(offset, 2, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork()),
                                    read(offset, 4, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork()).substring(2),
                                    read(offset, 4, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork()).substring(2)
                            );
                            switch (iPv4Header.getProtocol()) {
                                case ICMP -> {
                                    ICMP icmp = new ICMP(
                                            Integer.decode(read(offset, 1, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            Integer.decode(read(offset, 1, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork()),
                                            Integer.decode(read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            Integer.decode(read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            Integer.decode(read(offset, 8, hexString)),
                                            read(offset, 48, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork()),
                                            ethernetHeader,
                                            iPv4Header
                                    );
                                    data.put(pcapPacketHeader, icmp);
                                }
                                case UDP -> {
                                    UDP udp = new UDP(
                                            Integer.decode(read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            Integer.decode(read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            Integer.decode(read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            read(offset, 2, hexString, llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())
                                    );
                                    offset += 2 * (pcapPacketHeader.getuInclLen() -
                                            EthernetHeader.getSIZE() -
                                            IPv4Header.getSIZE() -
                                            UDP.getSIZE());
                                }
                                case TCP -> {
                                    TCP tcp = new TCP(
                                            Integer.decode(read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            Integer.decode(read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            Long.decode(read(offset, 4, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            Long.decode(read(offset, 4, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork()).substring(2),
                                            Integer.decode(read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork())),
                                            read(offset, 2, hexString, llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork()),
                                            Integer.decode(read(offset, 2, hexString,
                                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                                    pcapGlobalHeader.getuNetwork()))
                                    );
                                    System.out.println("** Packet TCP **");
                                    System.out.println("Source Port = " + tcp.getSourcePort());
                                    System.out.println("Destination Port = " + tcp.getDestinationPort());
                                    System.out.println("Sequence Number = " + tcp.getSequence());
                                    System.out.println("Offset = " + tcp.getOffset());
                                    System.out.println("TCP Flags = ");
                                    System.out.println("\tURG = " + tcp.getFlags().getUrg());
                                    System.out.println("\tACK = " + tcp.getFlags().getAck());
                                    System.out.println("\tPSH = " + tcp.getFlags().getPsh());
                                    System.out.println("\tRST = " + tcp.getFlags().getRst());
                                    System.out.println("\tSYN = " + tcp.getFlags().getSyn());
                                    System.out.println("\tFIN = " + tcp.getFlags().getFin());
                                    System.out.println("Window = " + tcp.getWindow());
                                    System.out.println("Checksum = " + tcp.getChecksum());
                                    System.out.println("Pointer = " + tcp.getPointer());
                                    offset += 2 * (pcapPacketHeader.getuInclLen() -
                                            EthernetHeader.getSIZE() -
                                            IPv4Header.getSIZE() -
                                            TCP.getSIZE());
                                }
                                default -> {
                                    System.err.println("Encapsulated protocol ("+iPv4Header.getProtocol()+") not implemented !");
                                    System.err.println("Skipping Packet Data...");
                                    offset += 2 * (pcapPacketHeader.getuInclLen() - EthernetHeader.getSIZE() - IPv4Header.getSIZE());
                                }
                            }
                        }
                        case ARP -> {
                            ARP arp = new ARP(null,
                                    null,
                                    ethernetHeader,
                                    null,
                                    Integer.decode(read(offset, 2, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())),
                                    read(offset, 2, hexString, llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork()),
                                    Integer.decode(read(offset, 1, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())),
                                    Integer.decode(read(offset, 1, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())),
                                    Integer.decode(read(offset, 2, hexString,llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork())),
                                    read(offset, 6, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                                    read(offset, 4, hexString, llh -> llh == LinkLayerHeader.ETHERNET,
                                            pcapGlobalHeader.getuNetwork()).substring(2),
                                    read(offset, 6, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                                    read(offset, 4, hexString,
                                            llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                                    pcapPacketHeader.getuInclLen() - EthernetHeader.getSIZE() - ARP.getSIZE() > 0 ?
                                            read(offset, 18, hexString, llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()) : "" );
                            data.put(pcapPacketHeader, arp);
                        }
                        default -> {
                            System.err.println("Ether Type ("+ethernetHeader.getEtherType()+") not implemented !");
                            System.err.println("Skipping Packet Data...");
                            offset += 2 * (pcapPacketHeader.getuInclLen() - EthernetHeader.getSIZE());
                        }
                    }
                }
                default -> {
                    System.err.println("Data Link Type ("+pcapGlobalHeader.getuNetwork()+") not implemented !");
                    System.err.println("Skipping Packet Data...");
                    offset += 2 * pcapPacketHeader.getuInclLen();
                }
            }
        }

        return new Pcap(pcapGlobalHeader, data);
    }
}
