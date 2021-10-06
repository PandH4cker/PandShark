package core;

import utils.file.FileToHex;

import java.nio.file.Path;

public class PcapReader {
    PcapReader(final String pcap) {
        String hexString = FileToHex.fileToHex(Path.of(pcap));
        System.out.println(hexString);
    }

    public static void main(String[] args) {
        new PcapReader(args[0]);
    }
}
