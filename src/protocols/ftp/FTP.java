package protocols.ftp;

import core.headers.layer2.Layer2Protocol;
import core.headers.layer3.Layer3Protocol;
import protocols.PcapPacketData;
import utils.hex.Hexlifier;

public class FTP extends PcapPacketData {
    private String message;

    public FTP(final Integer id,
                  final Long sequenceNumber,
                  final Layer2Protocol layer2Protocol,
                  final Layer3Protocol layer3Protocol,
                  final String message) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol);
        this.message = Hexlifier.unhexlify(message);
    }

    @Override
    public String toString() {
        return (Character.isDigit(this.message.charAt(0)) ? "Response: " : "Request: ") +
               this.message;
    }
}
