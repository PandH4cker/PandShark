package core.formats;

import core.headers.PcapGlobalHeader;
import core.headers.PcapPacketData;
import core.headers.PcapPacketHeader;
import utils.bytes.Bytefier;
import utils.bytes.Swapper;
import utils.hex.Hexlifier;

import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;


public class Pcap {
    private static final String SWAPPED_HEX = "0xd4c3b2a1";

    private PcapGlobalHeader globalHeader;
    private HashMap<PcapPacketHeader, PcapPacketData> data;

    public Pcap(final PcapGlobalHeader globalHeader,
                final HashMap<PcapPacketHeader, PcapPacketData> data) {
        this.globalHeader = globalHeader;
        this.data = data;
    }

    public static Pcap fromHexString(String hexString) {
        //Global Header
        String magicNumber;
        Integer uVersionMajor, uVersionMinor,
                thisZone, uSigFigs, uSnapLen, uNetwork;
        int i = 0;
        StringBuilder hex = new StringBuilder();

        //Magic Number
        int offset = 0;
        for(; i < 8; ++i)
            hex.append(hexString.charAt(i));
        magicNumber = "0x" + hex.toString().toLowerCase();
        hex.setLength(0);
        offset+= i;

        //Version Major
        for(; i < offset + 4; ++i)
            hex.append(hexString.charAt(i));
        uVersionMajor = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode(Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());

        System.out.println("** Global Header **");
        System.out.println("Magic Number = "+magicNumber);
        System.out.println("Version Major = " + uVersionMajor);
        return null;
    }
}
