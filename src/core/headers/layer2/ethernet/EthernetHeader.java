package core.headers.layer2.ethernet;

import core.formats.Pcap;
import core.headers.layer2.Layer2Protocol;
import core.headers.layer2.ethernet.exceptions.UnknownEtherType;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;
import utils.net.MAC;

public class EthernetHeader implements Layer2Protocol {
    private static final Integer SIZE = 14;

    private String destinationIP; //6 bytes
    private String sourceIP; //6 bytes
    private EtherType etherType; //2 bytes
    private String reserved; //2 bytes
    private EtherType etherType2; //2 bytes

    public EthernetHeader(final String destinationIP,
                          final String sourceIP,
                          final String etherType) {
        this.destinationIP = MAC.fromHexString(destinationIP);
        this.sourceIP = MAC.fromHexString(sourceIP);
        try {
            this.etherType = EtherType.fromCodeType(etherType);
        } catch (UnknownEtherType e) {
            this.etherType = EtherType.UNKNOWN;
        }
        this.reserved = "";
        this.etherType2 = null;
    }

    public EthernetHeader(final String destinationIP,
                          final String sourceIP,
                          final String etherType,
                          final String reserved,
                          final String etherType2) {
        this.destinationIP = MAC.fromHexString(destinationIP);
        this.sourceIP = MAC.fromHexString(sourceIP);
        try {
            this.etherType = EtherType.fromCodeType(etherType);
        } catch (UnknownEtherType e) {
            this.etherType = EtherType.UNKNOWN;
        }
        this.reserved = reserved;
        try {
            this.etherType2 = EtherType.fromCodeType(etherType2);
        } catch (UnknownEtherType e) {
            this.etherType2 = EtherType.UNKNOWN;
        }
    }

    public static Integer getSIZE() {
        return SIZE;
    }

    public static EthernetHeader readEthernetHeader(String hexString, PcapGlobalHeader pcapGlobalHeader) {
        return new EthernetHeader(
                Pcap.read(Pcap.offset, 6, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 6, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork()).substring(2),
                Pcap.read(Pcap.offset, 2, hexString,
                        llh -> llh == LinkLayerHeader.ETHERNET,
                        pcapGlobalHeader.getuNetwork())
        );
    }

    @Override
    public String toString() {
            return "\tDestination IP: " + destinationIP +
            "\n\tSource IP: " + sourceIP +
            "\n\tEtherType: " + etherType.getCodeType() + " (" + etherType + ")";
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
