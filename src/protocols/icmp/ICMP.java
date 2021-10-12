package protocols.icmp;

import core.headers.layer2.Layer2Protocol;
import core.headers.layer3.Layer3Protocol;
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
                final Integer sequenceNumber,
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

    @Override
    public String toString() {
        return new StringBuilder()
                .append("Type/Code Combination = (")
                .append(this.typeCodeCombination.getType())
                .append(",").append(this.typeCodeCombination.getCode()).append(") ")
                .append(this.typeCodeCombination).append("\nChecksum = ")
                .append(this.checksum).append("\nIdentifier = ")
                .append(this.getId()).append("\nSequence Number = ")
                .append(this.getSequenceNumber()).append("\n")
                .append("Data = ").append(Hexlifier.unhexlify(this.getData())).toString();
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
