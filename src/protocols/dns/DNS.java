package protocols.dns;

import core.headers.layer2.Layer2Protocol;
import core.headers.layer3.Layer3Protocol;
import protocols.PcapPacketData;
import protocols.dns.query.DNSQuery;

public class DNS extends PcapPacketData {
    private String identifier;
    private DNSFlags dnsFlags;
    private Integer qdCount;
    private Integer anCount;
    private Integer nsCount;
    private Integer arCount;
    private DNSQuery query;


    protected DNS(final String identifier,
                  final String dnsFlags,
                  final Integer qdCount,
                  final Integer anCount,
                  final Integer nsCount,
                  final Integer arCount,
                  final String query,
                  final Integer id,
                  final Integer sequenceNumber,
                  final Layer2Protocol layer2Protocol,
                  final Layer3Protocol layer3Protocol) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol);
    }
}
