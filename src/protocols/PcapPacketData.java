package protocols;

import core.headers.layer2.Layer2Protocol;
import core.headers.layer3.Layer3Protocol;
import core.headers.layer4.Layer4Protocol;

public abstract class PcapPacketData implements Comparable {
    private Layer2Protocol layer2Protocol;
    private Layer3Protocol layer3Protocol;
    private Layer4Protocol layer4Protocol;
    private Integer id;
    private Long sequenceNumber;

    protected PcapPacketData(final Integer id,
                             final Long sequenceNumber,
                             final Layer2Protocol layer2Protocol,
                             final Layer3Protocol layer3Protocol) {
        this.id = id;
        this.sequenceNumber = sequenceNumber;
        this.layer2Protocol = layer2Protocol;
        this.layer3Protocol = layer3Protocol;
    }

    protected PcapPacketData(final Integer id,
                             final Long sequenceNumber,
                             final Layer2Protocol layer2Protocol,
                             final Layer3Protocol layer3Protocol,
                             final Layer4Protocol layer4Protocol) {
        this.id = id;
        this.sequenceNumber = sequenceNumber;
        this.layer2Protocol = layer2Protocol;
        this.layer3Protocol = layer3Protocol;
        this.layer4Protocol = layer4Protocol;
    }


    @Override
    public int compareTo(Object o) {
        PcapPacketData p = (PcapPacketData) o;
        return this.sequenceNumber.compareTo(p.sequenceNumber);
    }

    public Layer4Protocol getLayer4Protocol() {
        return layer4Protocol;
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

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(Long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }
}
