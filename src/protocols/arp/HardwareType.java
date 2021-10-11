package protocols.arp;

import protocols.arp.exceptions.UnknownHardwareType;

public enum HardwareType {
    ETHERNET(1, "Ethernet (10Mb)"),
    EXPERIMENTAL_ETHERNET(2, "Experimental Ethernet (3Mb)"),
    AX25(3, "Amateur Radio AX.25"),
    PPNTR(4, "Proteon ProNET Token Ring"),
    CHAOS(5, "Chaos"),
    IEEE802(6, "IEEE 802 Networks"),
    ARCNET(7, "ARCNET"),
    HYPERCHANNEL(8, "Hyperchannel"),
    LANSTAR(9, "Lanstar"),
    ASA(10, "Autonet Short Address"),
    LOCALTALK(11, "LocalTalk"),
    LOCALNET(12, "LocalNet"),
    ULTRA_LINK(13, "Ultra link"),
    SMDS(14, "SMDS"),
    FRAME_RELAY(15, "Frame Relay"),
    ATM(16, "Asynchronous Transmission Mode"),
    HDLC(17, "HDLC"),
    FIBRE_CHANNEL(18, "Fibre Channel"),
    ATM_RFC2225(19, "Asynchronous Transmission Mode"),
    SERIAL_LINE(20, "Serial Line"),
    ATM_MXB1(21, "Asynchronous Transmission Mode"),
    MIL_STD(22, "MIL-STD-188-220"),
    METRICOM(23, "Metricom"),
    IEEE1394(24, "IEEE 1394.1995"),
    MAPOS(25, "MAPOS"),
    TWINAXIAL(26, "Twinaxial"),
    EUI64(27, "EUI-64"),
    HIPARP(28, "HIPARP"),
    IP_ARPOISO(29, "IP and ARP over ISO 7816-3"),
    ARPSEC(30, "ARPSec"),
    IPSEC(31, "IPsec tunnel"),
    INFINIBAND(32, "InfiniBand"),
    CAI(33, "Common Air Interface");

    private Integer code;
    private String name;

    HardwareType(final Integer code, final String name) {
        this.code = code;
        this.name = name;
    }

    public Integer getCode() {
        return code;
    }

    @Override
    public String toString() {
        return name;
    }

    public static HardwareType fromCode(final Integer code) throws UnknownHardwareType {
        for(HardwareType ht : HardwareType.values())
            if (ht.code.equals(code))
                return ht;
        throw new UnknownHardwareType("HardwareType ("+code+") unknown");
    }
}
