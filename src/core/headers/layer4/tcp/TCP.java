package core.headers.layer4.tcp;

import core.formats.Pcap;
import core.headers.layer4.Layer4Protocol;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;
import utils.bytes.Bytefier;

public class TCP implements Layer4Protocol {
    private static final Integer SIZE = 20;

    private Integer sourcePort;
    private Integer destinationPort;
    private Long sequence;
    private Long ackNumber;
    private Integer offset;
    private String reserved;
    private TCPFlags flags;
    private Integer window;
    private String checksum;
    private Integer pointer;

    //Optional
    private String option;

    public TCP(final Integer sourcePort,
               final Integer destinationPort,
               final Long sequence,
               final Long ackNumber,
               final String offResFlags,
               final Integer window,
               final String checksum,
               final Integer pointer) {
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.sequence = sequence;
        this.ackNumber = ackNumber;
        this.window = window;
        this.checksum = checksum;
        this.pointer = pointer;

        byte[] offResFlagsByteArray = Bytefier.hexStringToByteArray(offResFlags);

        this.offset = ((offResFlagsByteArray[0] & 0xFF) >> 4) * 4;
        this.reserved = String.valueOf(Bytefier.getFourthLowest(offResFlagsByteArray[0])) +
                Bytefier.getBit(offResFlagsByteArray[1], 7) +
                Bytefier.getBit(offResFlagsByteArray[1], 6);
        this.flags = new TCPFlags(Bytefier.getBit(offResFlagsByteArray[1], 5) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 4) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 3) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 2) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 1) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 0) != 0);
    }

    public static TCP readTcp(String hexString, PcapGlobalHeader pcapGlobalHeader) {
        return new TCP(
                Integer.decode(Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Integer.decode(Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Long.decode(Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Long.decode(Pcap.read(Pcap.offset, 4, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()).substring(2),
                Integer.decode(Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())),
                Pcap.read(Pcap.offset, 2, hexString, llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()),
                Integer.decode(Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()))
        );
    }

    public String getOption() {
        return option;
    }

    public void setOption(String option) {
        this.option = option;
    }

    @Override
    public String toString() {
        return "Source Port = " + this.sourcePort +
        "\nDestination Port = " + this.destinationPort +
        "\nSequence Number = " + this.sequence +
        "\nAck Number = " + this.ackNumber +
        "\nOffset = " + this.offset +
        "\nTCP Flags = " +
        "\n\tURG = " + this.flags.getUrg() +
        "\n\tACK = " + this.flags.getAck() +
        "\n\tPSH = " + this.flags.getPsh() +
        "\n\tRST = " + this.flags.getRst() +
        "\n\tSYN = " + this.flags.getSyn() +
        "\n\tFIN = " + this.flags.getFin() +
        "\nWindow = " + this.window +
        "\nChecksum = " + this.checksum +
        "\nPointer = " + this.pointer;
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

    public Long getSequence() {
        return sequence;
    }

    public void setSequence(Long sequence) {
        this.sequence = sequence;
    }

    public Long getAckNumber() {
        return ackNumber;
    }

    public void setAckNumber(Long ackNumber) {
        this.ackNumber = ackNumber;
    }

    public Integer getOffset() {
        return offset;
    }

    public void setOffset(Integer offset) {
        this.offset = offset;
    }

    public String getReserved() {
        return reserved;
    }

    public void setReserved(String reserved) {
        this.reserved = reserved;
    }

    public TCPFlags getFlags() {
        return flags;
    }

    public void setFlags(TCPFlags flags) {
        this.flags = flags;
    }

    public Integer getWindow() {
        return window;
    }

    public void setWindow(Integer window) {
        this.window = window;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
    }

    public Integer getPointer() {
        return pointer;
    }

    public void setPointer(Integer pointer) {
        this.pointer = pointer;
    }
}
