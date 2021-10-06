package protocols.icmp;

import core.headers.PcapPacketData;

public class ICMP extends PcapPacketData {
    private Integer type;
    private Integer code;
    private Integer checksum;

    protected ICMP(final Integer type,
                   final Integer code,
                   final Integer checksum,
                   final Integer id,
                   final Integer sequenceNumber) {
        super(id, sequenceNumber);
        this.type = type;
        this.code = code;
        this.checksum = checksum;
    }

}
