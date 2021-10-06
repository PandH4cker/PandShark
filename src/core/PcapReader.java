package core;

import utils.file.FileToHex;

public class PcapReader {
    PcapReader(final String pcap) {
        String hexString = FileToHex.fileToHexString(pcap);
        System.out.println(hexString);
    }

    public static void main(String[] args) {
        new PcapReader(args[0]);
    }
}
