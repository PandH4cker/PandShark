package protocols;

public abstract class PcapPacketData {
    private Integer id;
    private Integer sequenceNumber;

    protected PcapPacketData(final Integer id, final Integer sequenceNumber) {
        this.id = id;
        this.sequenceNumber = sequenceNumber;
    }

    protected Integer getId() {
        return id;
    }

    protected void setId(Integer id) {
        this.id = id;
    }

    protected Integer getSequenceNumber() {
        return sequenceNumber;
    }

    protected void setSequenceNumber(Integer sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }
}
