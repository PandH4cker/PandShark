package protocols.http;

import core.formats.Pcap;
import core.headers.layer2.Layer2Protocol;
import core.headers.layer2.ethernet.EthernetHeader;
import core.headers.layer3.Layer3Protocol;
import core.headers.layer3.ip.v4.IPv4Header;
import core.headers.layer4.tcp.TCP;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;
import protocols.PcapPacketData;
import utils.hex.Hexlifier;

import java.util.Arrays;
import java.util.stream.Collectors;

public class HTTP extends PcapPacketData {
    private String httpMessage;

    protected HTTP(final String httpMessage,
                   Integer id,
                   Long sequenceNumber,
                   Layer2Protocol layer2Protocol,
                   Layer3Protocol layer3Protocol) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol);
        String[] splittedHeaders = httpMessage.split("0D0A");

        this.httpMessage = Arrays.stream(splittedHeaders)
                                 .map(Hexlifier::unhexlify)
                                 .collect(Collectors.joining("\n"));
    }

    public static HTTP readHTTP(String hexString, PcapGlobalHeader pcapGlobalHeader, EthernetHeader ethernetHeader, IPv4Header iPv4Header, TCP tcp, Integer size) {
        return new HTTP(Pcap.read(Pcap.offset, size, hexString, llh -> llh == LinkLayerHeader.ETHERNET, pcapGlobalHeader.getuNetwork()).substring(2),
                        iPv4Header.getIdentification(),
                        tcp.getSequence(),
                        ethernetHeader,
                        iPv4Header);
    }


    public String getHttpMessage() {
        return httpMessage;
    }
}
