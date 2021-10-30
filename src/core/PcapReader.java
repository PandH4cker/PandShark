package core;

import core.formats.Pcap;
import core.headers.layer2.ethernet.EthernetHeader;
import core.headers.layer3.ip.v4.IPv4Header;
import core.headers.layer4.tcp.TCP;
import core.headers.layer4.udp.UDP;
import core.headers.pcap.PcapPacketHeader;
import protocols.PcapPacketData;
import protocols.arp.ARP;
import protocols.dhcp.DHCP;
import protocols.dhcp.option.codes.messagetype.DHCPMessageType;
import protocols.dns.DNS;
import protocols.ftp.FTP;
import protocols.http.HTTP;
import protocols.icmp.ICMP;
import utils.file.FileToHex;
import utils.prompt.Prompt;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public class PcapReader {
    private Pcap pcap;

    PcapReader(final String pcapPath) {
        String hexString = FileToHex.fileToHexString(pcapPath);
        this.pcap = Pcap.fromHexString(hexString);
        System.out.println(pcap.getData().size() + " packets read");
    }

    public void displayPackets() {
        int index = 1;
        for (Map.Entry<PcapPacketHeader, PcapPacketData> dataEntry : this.pcap.getData().entrySet()) {
            PcapPacketHeader packetHeader = dataEntry.getKey();
            PcapPacketData packetData = dataEntry.getValue();
            System.out.println(
                    index + "\t" + switch (pcap.getGlobalHeader().getuNetwork()) {
                        case ETHERNET -> {
                            EthernetHeader ethernetHeader = (EthernetHeader) packetData.getLayer2Protocol();
                            yield switch (ethernetHeader.getEtherType()) {
                                case IPV4 -> {
                                    IPv4Header iPv4Header = (IPv4Header) packetData.getLayer3Protocol();
                                    yield iPv4Header.getSourceIP() + " -> " +
                                            iPv4Header.getDestinationIP() + "\t" +
                                            (!Arrays.asList("UDP", "TCP").contains(iPv4Header.getProtocol().toString())
                                                    ? iPv4Header.getProtocol() + " " : "") +
                                            switch (iPv4Header.getProtocol()) {
                                                case ICMP -> ((ICMP) packetData).getTypeCodeCombination() + "\t" +
                                                        "id=" + packetData.getId() + ", seq=" + packetData.getSequenceNumber() +
                                                        ", ttl=" + iPv4Header.getTtl();
                                                case TCP -> {
                                                    if (packetData instanceof FTP) {
                                                        yield "FTP " + packetHeader.getuInclLen() + " " + packetData;
                                                    } else if (packetData instanceof HTTP) {
                                                        yield "HTTP " + packetHeader.getuInclLen() + " " + packetData.toString().split("\n")[0];
                                                    }
                                                    yield null;
                                                }
                                                case UDP -> {
                                                    if (packetData instanceof DNS) {
                                                        String dnsOutputString =  "DNS " + packetHeader.getuInclLen() + " " +
                                                                ((DNS) packetData).getDnsFlags().getOpcode() + " " +
                                                                ((DNS) packetData).getIdentifier() + " " +
                                                                ((DNS) packetData).getQueries().get(0).getQueryType().getEntry() + " " +
                                                                ((DNS) packetData).getQueries().get(0).getName();
                                                        dnsOutputString += ((DNS) packetData).getAnswers()
                                                         .stream()
                                                         .map(ans ->
                                                                 " " + ans.getType().getEntry() +
                                                                         " " + ans.getData()
                                                                         .replaceAll("\n", " "))
                                                                         .collect(Collectors.joining());
                                                        yield dnsOutputString;
                                                    } else if (packetData instanceof DHCP) {
                                                        yield "DHCP " + packetHeader.getuInclLen() + " DHCP " +
                                                                ((DHCPMessageType) ((DHCP) packetData).getOption()
                                                                                                      .get(0))
                                                                        .getMessageType() + "\t" +
                                                                "- Transaction ID " + ((DHCP) packetData).getTransactionID();
                                                    }
                                                    yield null;
                                                }
                                                default -> null;
                                            };
                                }
                                case ARP -> {
                                    ARP arp = (ARP) packetData;
                                    yield arp.getSenderHardwareAddress() + " -> " + arp.getTargetHardwareAddress() +
                                            "\t ARP " + packetHeader.getuInclLen() + " " + arp.getInfo();
                                }
                                default -> null;
                            };
                        }
                        default -> null;
                    }
            );
            ++index;
        }
    }

    public void displayHelp() {
        System.out.println(
                "display [frameNumber]\tDisplay all the packets read or the nth packets\n" +
                "help\tDisplay this help prompt\n" +
                        "exit\tQuit the program"
        );
    }

    public static void main(String[] args) {
        PcapReader reader = new PcapReader(args[0]);
        while (true) {
            switch (Prompt.prompt("PandShark >> ")) {
                case "display" -> reader.displayPackets();
                case String s && s.startsWith("display") -> {
                    String[] splittedCmd = s.split(" ");
                    if (splittedCmd.length >= 2) {
                        try {
                            int frameNumber = Integer.parseInt(splittedCmd[1]);
                            PcapPacketData data = (PcapPacketData) reader.pcap.getData().values().toArray()[frameNumber - 1];
                            PcapPacketHeader packetHeader = (PcapPacketHeader) reader.pcap.getData().keySet().toArray()[frameNumber - 1];
                            System.out.println("Frame " + frameNumber + ": " +
                                                packetHeader.getuInclLen() + " bytes on wire (" +
                                                (packetHeader.getuInclLen() * 8) + " bits)");
                            System.out.println("\tEncapsulation type: Ethernet (1)");

                            EthernetHeader ethernetHeader = (EthernetHeader) data.getLayer2Protocol();
                            System.out.println("** Ethernet Header **");
                            System.out.println(ethernetHeader);

                            switch (ethernetHeader.getEtherType()) {
                                case IPV4 -> {
                                    IPv4Header iPv4Header = (IPv4Header) data.getLayer3Protocol();
                                    System.out.println("** IPv4 Header **");
                                    System.out.println(iPv4Header);
                                    switch (iPv4Header.getProtocol()) {
                                        case ICMP -> {
                                            ICMP icmp = (ICMP) data;
                                            System.out.println("** ICMP Header **");
                                            System.out.println(icmp);
                                        }
                                        case TCP -> {
                                            TCP tcp = (TCP) data.getLayer4Protocol();
                                            System.out.println("** TCP Header **");
                                            System.out.println(tcp);

                                            if (data instanceof FTP) {
                                                System.out.println("** FTP Header **");
                                                System.out.println("\t" + data);
                                            } else if (data instanceof HTTP) {
                                                System.out.println("** HTTP Header **");
                                                System.out.println(data);
                                            } else if (data instanceof DNS) {
                                                System.out.println("** DNS Header **");
                                                System.out.println(data);
                                            }
                                        }
                                        case UDP -> {
                                            UDP udp = (UDP) data.getLayer4Protocol();
                                            System.out.println("** UDP Header **");
                                            System.out.println(udp);

                                            if (data instanceof DNS) {
                                                System.out.println("** DNS Header **");
                                                System.out.println(data);
                                            } else if (data instanceof DHCP) {
                                                System.out.println("** DHCP Header **");
                                                System.out.println(data);
                                            }
                                        }
                                    }
                                }
                                case ARP -> {
                                    ARP arp = (ARP) data;
                                    System.out.println("** ARP Header **");
                                    System.out.println(arp);
                                }
                            }
                        } catch (ArrayIndexOutOfBoundsException | NumberFormatException ignored) {
                            reader.displayHelp();
                        }
                    }
                }
                case "exit" -> {
                    return;
                }
                case "help" -> reader.displayHelp();
                default -> reader.displayHelp();
            }
        }
    }
}
