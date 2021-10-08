package core.formats;

import core.headers.*;
import utils.bytes.Swapper;
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
        offset = i;

        //Version Major
        for(; i < offset + 4; ++i)
            hex.append(hexString.charAt(i));
        uVersionMajor = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode(Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        for(; i < offset + 4; ++i)
            hex.append(hexString.charAt(i));
        uVersionMinor = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode(Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        for(; i < offset + 8; ++i)
            hex.append(hexString.charAt(i));
        thisZone = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode(Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        for(; i < offset + 8; ++i)
            hex.append(hexString.charAt(i));
        uSigFigs = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode(Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        for(; i < offset + 8; ++i)
            hex.append(hexString.charAt(i));
        uSnapLen = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode(Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        for(; i < offset + 8; ++i)
            hex.append(hexString.charAt(i));
        uNetwork = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode(Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        PcapGlobalHeader pcapGlobalHeader = new PcapGlobalHeader(
                magicNumber, uVersionMajor, uVersionMinor, thisZone, uSigFigs, uSnapLen, uNetwork
        );

        System.out.println(pcapGlobalHeader);

        //Packet Header
        Integer uTsSec, uTsUsec, uIncLen, uOrigLen;
        for(; i < offset + 8; ++i)
            hex.append(hexString.charAt(i));
        uTsSec = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode("0x"+Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        for(; i < offset + 8; ++i)
            hex.append(hexString.charAt(i));
        uTsUsec = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode("0x"+Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        for(; i < offset + 8; ++i)
            hex.append(hexString.charAt(i));
        uIncLen = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode(Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        for(; i < offset + 8; ++i)
            hex.append(hexString.charAt(i));
        uOrigLen = magicNumber.equals(SWAPPED_HEX) ?
                Integer.decode(Swapper.swappedHexString(hex.toString())) :
                Integer.decode(hex.toString());
        hex.setLength(0);
        offset = i;

        PcapPacketHeader packetHeader = new PcapPacketHeader(uTsSec, uTsUsec, uIncLen, uOrigLen);
        System.out.println(packetHeader);

        /*String preambul;

        for(; i < offset + 25; ++i)
            hex.append(hexString.charAt(i));
        preambul = magicNumber.equals(SWAPPED_HEX) ?
                Swapper.swappedHexString(hex.toString()) :
                hex.toString();
        hex.setLength(0);
        offset = i;

        System.out.println(preambul);*/
        return null;
    }
}
