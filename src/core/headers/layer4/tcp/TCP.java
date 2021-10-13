package core.headers.layer4.tcp;

import core.headers.layer4.Layer4Protocol;
import utils.bytes.Bytefier;

public class TCP implements Layer4Protocol {
    private static final Integer SIZE = 20;

    private Integer sourcePort;
    private Integer destinationPort;
    private Integer sequence;
    private Integer ackNumber;
    private Integer offset;
    private String reserved;
    private TCPFlags flags;
    private Integer window;
    private String checksum;
    private Integer pointer;

    public TCP(final Integer sourcePort,
               final Integer destinationPort,
               final Integer sequence,
               final Integer ackNumber,
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
        this.offset = (int) Bytefier.getFourthHighest(offResFlagsByteArray[0]);
        this.reserved = String.valueOf(Bytefier.getFourthLowest(offResFlagsByteArray[0])) +
                Bytefier.getBit(offResFlagsByteArray[1], 0) +
                Bytefier.getBit(offResFlagsByteArray[1], 1);
        this.flags = new TCPFlags(Bytefier.getBit(offResFlagsByteArray[1], 2) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 3) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 4) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 5) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 6) != 0,
                Bytefier.getBit(offResFlagsByteArray[1], 7) != 0);
    }
}
