package core.formats;

import core.headers.ethernet.EthernetHeader;
import core.headers.pcap.LinkLayerHeader;
import core.headers.pcap.PcapGlobalHeader;
import core.headers.pcap.PcapPacketHeader;
import protocols.PcapPacketData;
import utils.bytes.Swapper;

import java.util.HashMap;
import java.util.function.Predicate;


public class Pcap {
    private static final String SWAPPED_HEX = "0xd4c3b2a1";
    private static int offset;
    private static String magicNumber = "";

    private PcapGlobalHeader globalHeader;
    private HashMap<PcapPacketHeader, PcapPacketData> data;

    public Pcap(final PcapGlobalHeader globalHeader,
                final HashMap<PcapPacketHeader, PcapPacketData> data) {
        this.globalHeader = globalHeader;
        this.data = data;
    }

    private static String read(int i, int bytesRead, String hexString) {
        StringBuilder hex = new StringBuilder();
        for(; i < offset + bytesRead; ++i) hex.append(hexString.charAt(i));
        offset = i;
        return magicNumber.isEmpty() ? "0x" + hex.toString().toLowerCase() :
                magicNumber.equals(SWAPPED_HEX) ? "0x" + Swapper.swappedHexString(hex.toString()) :
                        "0x" + hex;
    }

    private static String read(int i, int bytesRead, String hexString,
                               Predicate<LinkLayerHeader> llhPredicate, LinkLayerHeader llh) {
        StringBuilder hex = new StringBuilder();
        for(; i < offset + bytesRead; ++i) hex.append(hexString.charAt(i));
        offset = i;
        return llhPredicate.test(llh) ? "0x" + hex : "0x" + Swapper.swappedHexString(hex.toString());
    }

    public static Pcap fromHexString(String hexString) {
        //Global Header
        magicNumber = read(offset, 8, hexString);
        PcapGlobalHeader pcapGlobalHeader = new PcapGlobalHeader(
                magicNumber, Integer.decode(read(offset, 4, hexString)),
                Integer.decode(read(offset, 4, hexString)),
                Integer.decode(read(offset, 8, hexString)),
                Integer.decode(read(offset, 8, hexString)),
                Integer.decode(read(offset, 8, hexString)),
                Integer.decode(read(offset, 8, hexString))
        );
        System.out.println(pcapGlobalHeader);

        while (offset < hexString.length()) {
            //Packet Header
            PcapPacketHeader pcapPacketHeader = new PcapPacketHeader(
                    Integer.decode(read(offset, 8, hexString)),
                    Integer.decode(read(offset, 8, hexString)),
                    Integer.decode(read(offset, 8, hexString)),
                    Integer.decode(read(offset, 8, hexString))
            );
            System.out.println(pcapPacketHeader);
            switch (pcapGlobalHeader.getuNetwork()) {
                case ETHERNET -> {
                    System.out.println("** Packet Data ("+pcapGlobalHeader.getuNetwork()+") **");
                    EthernetHeader ethernetHeader = new EthernetHeader(
                            read(offset, 12, hexString,
                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                    pcapGlobalHeader.getuNetwork()).substring(2),
                            read(offset, 12, hexString,
                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                    pcapGlobalHeader.getuNetwork()).substring(2),
                            read(offset, 4, hexString,
                                    llh -> llh == LinkLayerHeader.ETHERNET,
                                    pcapGlobalHeader.getuNetwork())
                    );
                    System.out.println(ethernetHeader);
                    offset += pcapPacketHeader.getuInclLen() * 2 - 28;
                }
                default -> {
                    System.err.println("Data Link Type ("+pcapGlobalHeader.getuNetwork()+") not implemented !");
                    System.err.println("Skipping Packet Data...");
                    offset += pcapPacketHeader.getuInclLen() * 2;
                }
            }
        }
        /*

        String destinationIP, sourceIP, etherType;

        for(; i < offset + 12; ++i)
            hex.append(hexString.charAt(i));
        destinationIP = hex.toString();
        hex.setLength(0);
        offset = i;

        for(; i < offset + 12; ++i)
            hex.append(hexString.charAt(i));
        sourceIP = hex.toString();
        hex.setLength(0);
        offset = i;

        for(; i < offset + 4; ++i)
            hex.append(hexString.charAt(i));
        etherType = hex.toString();
        hex.setLength(0);
        offset = i;

        try {
            System.out.println("** Packet Data ("+ LinkLayerHeader.fromDataLinkType(uNetwork)+") **");
        } catch (UnknownLinkLayerHeader e) {
            e.printStackTrace();
        }

        EthernetHeader ethernetHeader = new EthernetHeader(destinationIP, sourceIP, etherType);
        System.out.println(ethernetHeader);

        try {
            System.out.println("** Packet Data ("+ EtherType.fromCodeType(etherType)+") **");
        } catch (UnknownEtherType e) {
            e.printStackTrace();
        }*/


        return null;
    }
}
