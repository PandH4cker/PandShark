package core.formats;

import core.headers.PcapGlobalHeader;
import core.headers.PcapPacketData;
import core.headers.PcapPacketHeader;

import java.util.HashMap;


public class Pcap {
    private PcapGlobalHeader globalHeader;
    private HashMap<PcapPacketHeader, PcapPacketData> data;

    public Pcap(final PcapGlobalHeader globalHeader,
                final HashMap<PcapPacketHeader, PcapPacketData> data) {
        this.globalHeader = globalHeader;
        this.data = data;
    }

    public static Pcap fromHexString(String hexString) {
        return null;
    }
}
