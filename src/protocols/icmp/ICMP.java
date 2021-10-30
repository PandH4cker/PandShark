package protocols.icmp;

import core.formats.Pcap;
import core.headers.layer2.Layer2Protocol;
import core.headers.layer2.ethernet.EthernetHeader;
import core.headers.layer3.Layer3Protocol;
import core.headers.layer3.ip.v4.IPv4Header;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;
import protocols.PcapPacketData;
import protocols.icmp.exceptions.UnknownTypeCodeCombination;
import utils.hex.Hexlifier;

public class ICMP extends PcapPacketData {
    private static final Integer SIZE = 8;

    private TypeCodeCombination typeCodeCombination;
    private String checksum;
    private Integer dataTimestamp;
    private String data;

    public ICMP(final Integer type,
                final Integer code,
                final String checksum,
                final Integer id,
                final Long sequenceNumber,
                final Integer dataTimestamp,
                final String data,
                final Layer2Protocol layer2Protocol,
                final Layer3Protocol layer3Protocol) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol);
        try {
            this.typeCodeCombination = TypeCodeCombination.fromTypeCode(type, code);
        } catch (UnknownTypeCodeCombination e) {
            this.typeCodeCombination = null;
        }
        this.checksum = checksum;
        this.dataTimestamp = dataTimestamp;
        this.data = data;
    }

    public static ICMP readIcmp(String hexString, PcapGlobalHeader pcapGlobalHeader, EthernetHeader ethernetHeader, IPv4Header iPv4Header) {
        return new ICMP(
                Integer.decode(Pcap.read(Pcap.offset, 1, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Integer.decode(Pcap.read(Pcap.offset, 1, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()),
                Integer.decode(Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Long.decode(Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Integer.decode(Pcap.read(Pcap.offset, 8, hexString)),
                Pcap.read(Pcap.offset, 48, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()),
                ethernetHeader,
                iPv4Header
        );
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("\tType/Code Combination: (")
                .append(this.typeCodeCombination.getType())
                .append(",").append(this.typeCodeCombination.getCode()).append(") ")
                .append(this.typeCodeCombination).append("\n\tChecksum: ")
                .append(this.checksum).append("\n\tIdentifier: ")
                .append(this.getId()).append("\n\tSequence Number: ")
                .append(this.getSequenceNumber()).append("\n\t")
                .append("Data: ").append(Hexlifier.unhexlify(this.getData())).toString();
    }

    public String getData() {
        return data;
    }

    public Integer getDataTimestamp() {
        return dataTimestamp;
    }

    public String getChecksum() {
        return checksum;
    }

    public TypeCodeCombination getTypeCodeCombination() {
        return typeCodeCombination;
    }
}
