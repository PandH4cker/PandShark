package core;

import core.formats.Pcap;
import core.headers.layer2.ethernet.EthernetHeader;
import core.headers.layer3.ip.v4.IPv4Header;
import protocols.PcapPacketData;
import protocols.icmp.ICMP;
import utils.file.FileToHex;

public class PcapReader {
    private Pcap pcap;

    PcapReader(final String pcapPath) {
        String hexString = FileToHex.fileToHexString(pcapPath);
        Pcap pcap = Pcap.fromHexString(hexString);
        System.out.println(pcap.getData().size() + " packets red");
        int index = 1;
        for (PcapPacketData d : pcap.getData().values()) {
            System.out.println(
                    index + "\t" + switch (pcap.getGlobalHeader().getuNetwork()) {
                        case ETHERNET -> {
                            EthernetHeader ethernetHeader = (EthernetHeader) d.getLayer2Protocol();
                            yield switch (ethernetHeader.getEtherType()) {
                                case IPV4 -> {
                                    IPv4Header iPv4Header = (IPv4Header) d.getLayer3Protocol();
                                    yield iPv4Header.getSourceIP() + " -> " +
                                            iPv4Header.getDestinationIP() + "\t" +
                                            iPv4Header.getProtocol() + " " +
                                            switch (iPv4Header.getProtocol()) {
                                                case ICMP -> ((ICMP) d).getTypeCodeCombination() + "\t" +
                                                        "id=" + d.getId() + ", seq=" + d.getSequenceNumber() +
                                                        ", ttl=" + iPv4Header.getTtl();
                                                case IGMP -> null;
                                                case TCP -> null;
                                                case UDP -> null;
                                            };
                                }
                                default -> null;
                            };
                        }
                        default -> throw new IllegalStateException("Unexpected value: " + pcap.getGlobalHeader().getuNetwork());
                    }
            );
            ++index;
        }
    }

    public static void main(String[] args) {
        new PcapReader(args[0]);
    }
}
