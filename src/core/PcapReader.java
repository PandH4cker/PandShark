package core;

import core.formats.Pcap;
import protocols.PcapPacketData;
import utils.file.FileToHex;

public class PcapReader {
    private Pcap pcap;

    PcapReader(final String pcapPath) {
        String hexString = FileToHex.fileToHexString(pcapPath);
        Pcap pcap = Pcap.fromHexString(hexString);
        System.out.println(pcap.getData().size() + " packets red");
        for (PcapPacketData d : pcap.getData().values())
            System.out.println(d);
    }

    public static void main(String[] args) {
        new PcapReader(args[0]);
    }
}
