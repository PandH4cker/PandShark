package protocols.ftp;

import core.formats.Pcap;
import core.headers.layer2.Layer2Protocol;
import core.headers.layer2.ethernet.EthernetHeader;
import core.headers.layer3.Layer3Protocol;
import core.headers.layer3.ip.v4.IPv4Header;
import core.headers.layer4.Layer4Protocol;
import core.headers.layer4.tcp.TCP;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;
import protocols.PcapPacketData;
import utils.hex.Hexlifier;

public class FTP extends PcapPacketData {
    private String message;

    public FTP(final Integer id,
               final Long sequenceNumber,
               final Layer2Protocol layer2Protocol,
               final Layer3Protocol layer3Protocol,
               final Layer4Protocol layer4Protocol,
                  final String message) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol, layer4Protocol);
        this.message = Hexlifier.unhexlify(message);
    }

    public static FTP readFtp(String hexString, PcapGlobalHeader pcapGlobalHeader, EthernetHeader ethernetHeader, IPv4Header iPv4Header, TCP tcp, Integer size) {
        return new FTP(iPv4Header.getIdentification(), tcp.getSequence(), ethernetHeader, iPv4Header, tcp,
                          Pcap.read(Pcap.offset, size, hexString,
                                  llh -> llh == LinkLayerHeader.ETHERNET,
                                  pcapGlobalHeader.getuNetwork()));
    }

    @Override
    public String toString() {
        return (Character.isDigit(this.message.charAt(0)) ? "Response: " : "Request: ") +
               this.message;
    }
}
