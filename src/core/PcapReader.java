package core;

import core.formats.Pcap;
import utils.file.FileToHex;

public class PcapReader {
    private Pcap pcap;

    PcapReader(final String pcapPath) {
        String hexString = FileToHex.fileToHexString(pcapPath);
        Pcap pcap = Pcap.fromHexString(hexString);
    }

    public static void main(String[] args) {
        new PcapReader(args[0]);
    }
}
