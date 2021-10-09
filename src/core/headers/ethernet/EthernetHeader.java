package core.headers.ethernet;

import java.util.Arrays;

public class EthernetHeader {
    private String destinationIP; //6 bytes
    private String sourceIP; //6 bytes
    private EtherType etherType; //2 bytes
    private String reserved; //2 bytes
    private EtherType etherType2; //2 bytes

    public EthernetHeader(final String destinationIP,
                          final String sourceIP,
                          final String etherType) {
        this.destinationIP = destinationIP;
        this.sourceIP = sourceIP;
        try {
            this.etherType = EtherType.fromCodeType(etherType);
        } catch (UnknownEtherType e) {
            e.printStackTrace();
        }
        this.reserved = "";
        this.etherType2 = null;
    }

    public EthernetHeader(final String destinationIP,
                          final String sourceIP,
                          final String etherType,
                          final String reserved,
                          final String etherType2) {
        this.destinationIP = destinationIP;
        this.sourceIP = sourceIP;
        try {
            this.etherType = EtherType.fromCodeType(etherType);
        } catch (UnknownEtherType e) {
            e.printStackTrace();
        }
        this.reserved = reserved;
        try {
            this.etherType2 = EtherType.fromCodeType(etherType2);
        } catch (UnknownEtherType e) {
            e.printStackTrace();
        }
    }

    @Override
    public String toString() {
            return "Destination IP = " + String.join(":", Arrays.asList(destinationIP.split("(?<=\\G.{2})"))) +
            "\nSource IP = " + String.join(":", Arrays.asList(sourceIP.split("(?<=\\G.{2})"))) +
            "\nEtherType = " + etherType.getCodeType() + " (" + etherType + ")";
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

    public EtherType getEtherType() {
        return etherType;
    }

    public void setEtherType(EtherType etherType) {
        this.etherType = etherType;
    }

    public String getReserved() {
        return reserved;
    }

    public void setReserved(String reserved) {
        this.reserved = reserved;
    }

    public EtherType getEtherType2() {
        return etherType2;
    }

    public void setEtherType2(EtherType etherType2) {
        this.etherType2 = etherType2;
    }
}
