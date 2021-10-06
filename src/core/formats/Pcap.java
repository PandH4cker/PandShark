package core.formats;

import core.headers.PcapGlobalHeader;
import core.headers.PcapPacketData;
import core.headers.PcapPacketHeader;

import java.util.HashMap;


public class Pcap {
    private PcapGlobalHeader globalHeader;
    private HashMap<PcapPacketHeader, PcapPacketData> data;
}
