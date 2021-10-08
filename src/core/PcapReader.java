package core;

import core.formats.Pcap;
import utils.file.FileToHex;

public class PcapReader {
    private Pcap pcap;

    PcapReader(final String pcapPath) {
        //System.out.println(FileToHex.hexdump(pcapPath));
        String hexString = FileToHex.fileToHexString(pcapPath);
        System.out.println(hexString);
        Pcap pcap = Pcap.fromHexString(hexString);
    }

    public static void main(String[] args) {
        new PcapReader(args[0]);
    }
}
