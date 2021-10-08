package core.headers.ethernet;

import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.UnknownLinkLayerHeader;

import java.util.Arrays;

public class EthernetHeader {
    private String destinationIP; //6 bytes
    private String sourceIP; //6 bytes
    private String etherType; //2 bytes
    private String reserved; //2 bytes
    private String etherType2; //2 bytes

    public EthernetHeader(final String destinationIP,
                          final String sourceIP,
                          final String etherType) {
        this.destinationIP = destinationIP;
        this.sourceIP = sourceIP;
        this.etherType = etherType;
        this.reserved = "";
        this.etherType2 = "";
    }

    public EthernetHeader(final String destinationIP,
                          final String sourceIP,
                          final String etherType,
                          final String reserved,
                          final String etherType2) {
        this.destinationIP = destinationIP;
        this.sourceIP = sourceIP;
        this.etherType = etherType;
        this.reserved = reserved;
        this.etherType2 = etherType2;
    }

    @Override
    public String toString() {
        try {
            return "Destination IP = " + String.join(":", Arrays.asList(destinationIP.split("(?<=\\G.{2})"))) +
            "\nSource IP = " + String.join(":", Arrays.asList(sourceIP.split("(?<=\\G.{2})"))) +
            "\nEtherType = " + etherType + " (" + EtherType.fromCodeType(etherType) + ")";
        } catch (UnknownEtherType e) {
            return null;
        }
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public void setDestinationIP(String destinationIP) {
        this.destinationIP = destinationIP;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }

    public String getEtherType() {
        return etherType;
    }

    public void setEtherType(String etherType) {
        this.etherType = etherType;
    }

    public String getReserved() {
        return reserved;
    }

    public void setReserved(String reserved) {
        this.reserved = reserved;
    }

    public String getEtherType2() {
        return etherType2;
    }

    public void setEtherType2(String etherType2) {
        this.etherType2 = etherType2;
    }
}
