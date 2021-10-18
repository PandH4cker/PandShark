package core.headers.layer4.udp;

import core.formats.Pcap;
import core.headers.layer4.Layer4Protocol;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;

public class UDP implements Layer4Protocol {
    private static final Integer SIZE = 8;

    private Integer sourcePort;
    private Integer destinationPort;
    private Integer length;
    private String checksum;

    public UDP(final Integer sourcePort,
               final Integer destinationPort,
               final Integer length,
               final String checksum) {
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.length = length;
        this.checksum = checksum;
    }

    public static UDP readUdp(String hexString, PcapGlobalHeader pcapGlobalHeader) {
        return new UDP(
                Integer.decode(Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Integer.decode(Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Integer.decode(Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Pcap.read(Pcap.offset, 2, hexString, llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())
        );
    }

    @Override
    public String toString() {
        return "Source Port = " + this.sourcePort +
        "\nDestination Port = " + this.destinationPort +
        "\nLength = " + this.length +
        "\nChecksum = " + this.checksum;
    }

    public static Integer getSIZE() {
        return SIZE;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(Integer sourcePort) {
        this.sourcePort = sourcePort;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(Integer destinationPort) {
        this.destinationPort = destinationPort;
    }

    public Integer getLength() {
        return length;
    }

    public void setLength(Integer length) {
        this.length = length;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
    }
}
