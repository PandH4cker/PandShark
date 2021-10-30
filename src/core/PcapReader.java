package core;

import core.formats.Pcap;
import core.headers.layer2.ethernet.EthernetHeader;
import core.headers.layer3.ip.v4.IPv4Header;
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

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public class PcapReader {
    private Pcap pcap;

    PcapReader(final String pcapPath) {
        String hexString = FileToHex.fileToHexString(pcapPath);
        this.pcap = Pcap.fromHexString(hexString);
        System.out.println(pcap.getData().size() + " packets red");
        int index = 1;
        for (Map.Entry<PcapPacketHeader, PcapPacketData> dataEntry : pcap.getData().entrySet()) {
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

    public static void main(String[] args) {
        new PcapReader(args[0]);
    }
}
