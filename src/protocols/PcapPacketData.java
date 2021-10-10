package protocols;

import core.headers.layer2.Layer2Protocol;
import core.headers.layer3.Layer3Protocol;

public abstract class PcapPacketData implements Comparable {
    private Layer2Protocol layer2Protocol;
    private Layer3Protocol layer3Protocol;
    private Integer id;
    private Integer sequenceNumber;

    protected PcapPacketData(final Integer id,
                             final Integer sequenceNumber,
                             final Layer2Protocol layer2Protocol,
                             final Layer3Protocol layer3Protocol) {
        this.id = id;
        this.sequenceNumber = sequenceNumber;
        this.layer2Protocol = layer2Protocol;
        this.layer3Protocol = layer3Protocol;
    }

    @Override
    public int compareTo(Object o) {
        PcapPacketData p = (PcapPacketData) o;
        return this.sequenceNumber.compareTo(p.sequenceNumber);
    }

    public Layer2Protocol getLayer2Protocol() {
        return layer2Protocol;
    }

    public Layer3Protocol getLayer3Protocol() {
        return layer3Protocol;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(Integer sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }
}
