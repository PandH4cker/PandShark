package core.headers.pcap;

import core.headers.pcap.exceptions.UnknownLinkLayerHeader;

public enum LinkLayerHeader {
    NULL(0, "NULL"),
    ETHERNET(1, "Ethernet"),
    AX25(3, "AX25"),
    IEEE802_5(6, "IEEE 802.5"),
    ARCNET_BSD(7, "ARCNET BSD"),
    SLIP(8, "SLIP"),
    PPP(9, "PPP"),
    FDDI(10, "FDDI"),
    PPP_HDLC(50, "PPP in HDLC"),
    PPP_ETHER(51, "PPPoE"),
    ATM_RFC1483(100, "LLC/SNAP-encapsulated ATM"),
    RAW(101, "Raw IP"),
    C_HDLC(104, "Cisco PPP with HDLC"),
    IEEE802_11(105, "IEEE 802.11"),
    FRELAY(107, "Frame Relay"),
    LOOP(108, "OpenBSD Loopback"),
    LINUX_SLL(113, "Linux \"cooked\" capture"),
    LTALK(114, "Apple LocalTalk"),
    PFLOG(117, "OpenBSD pflog"),
    IEEE802_11_PRISM(119, "Prism monitor mode"),
    IP_OVER_FC(122, "IP-over-Fibre Channel"),
    SUNATM(123, "ATM traffic"),
    IEEE802_11_RADIOTAP(127, "Radiotap link-layer"),
    ARCNET_LINUX(129, "ARCNET Data Packet"),
    APPLE_IP_OVER_IEEE1394(138, "Apple IP-over-IEEE 1394 cooked"),
    MTP2_WITH_PHDR(139, "System 7 Message Transfer Part Level 2 pseudo-header"),
    MTP2(140, "System 7 Message Transfer Part Level 2"),
    MTP3(141, "System 7 Message Transfer Part Level 3"),
    SCCP(142, "System 7 Signalling Connection Control Part"),
    DOCSIS(143, "DOCSIS MAC"),
    LINUX_IRDA(144, "Linux-IrDA"),
    IEEE802_11_AVS(163, "AVS monitor mode"),
    BACNET_MS_TP(165, "BACnet MS/TP"),
    PPP_PPPD(166, "PPP in HDLC"),
    GPRS_LLC(169, "General Packet Radio Service Logical Link Control"),
    GPF_T(170, "Transparent-mapped"),
    GPF_F(171, "Frame-mapped"),
    LINUX_LAPD(177, "Link Access Procedures on the D Channel"),
    MFR(182, "Multi-Link Frame Relay"),
    BLUETOOTH_HCI_H4(187, "Bluetooth HCI UART"),
    USB_LINUX(189, "USB packet"),
    PPI(192, "Per-Packet Information"),
    IEEE802_15_4_WITHFCS(195, "IEEE 802.15.4"),
    SITA(196, "SITA"),
    ERF(197, "Endace ERF record"),
    BLUETOOTH_HDI_H4_WITH_PHDR(201, "Bluetooth HCI UART with pseudo header"),
    AX25_KISS(202, "AX25 1-byte KISS Header"),
    LAPD(203, "Link Access Procedures on the D Channel"),
    PPP_WITH_DIR(204, "PPP in HDLC"),
    C_HDLC_WITH_DIR(205, "Cisco PPP with HDLC"),
    FRELAY_WITH_DIR(206, "Frame Relay LAPF"),
    LAPB_WITH_DIR(207, "Link Access Procedure, Balanced"),
    IPMB_LINUX(209, "IPMB over I2C"),
    FLEXRAY(210, "FlexRay"),
    LIN(212, "Local Interconnect Network"),
    IEEE802_15_4_NONASK_PHY(215, "IEEE 802.15.4 Low-Rate Wireless Networks"),
    USB_LINUX_MMAPPED(220, "USB packet"),
    FC_2(224, "Fibre Channel FC-2"),
    FC_2_WITH_FRAME_DELIMS(225, "Fibre Channel FC-2 with Frame Delims"),
    IPNET(226, "Solaris ipnet pseudo-header"),
    CAN_SOCKETCAN(227, "Controller Area Network"),
    IPV4(228, "Raw IPv4"),
    IPV6(229, "Raw IPv6"),
    IEEE802_15_4_NOFCS(230, "IEEE 802.15.4 No FCS"),
    DBUS(231, "Raw D-Bus"),
    DVB_CI(235, "DVB Common Interface"),
    MUX27010(236, "Variant of 3GPP TS"),
    STANAG_5066_D_PDU(237, "D PDU"),
    NFLOG(239, "Linux netlink"),
    NETANALYZER(240, "netANALYZER"),
    NETANALYZER_TRANSPARENT(241, "Transparent-netANALYZER"),
    IPOIB(242, "IP-over-infiniBand"),
    MPEG_2_TS(243, "MPEG-2"),
    NG40(244, "ng4T GmbH"),
    NFC_LLCP(245, "NFC LLCP"),
    INFINIBAND(247, "Raw Infiniband"),
    SCTP(248, "SCTP"),
    USBPCAP(249, "USB packet with USBPcap Header"),
    RTAC_SERIAL(250, "Serial-line RTAC"),
    BLUETOOTH_LE_LL(251, "Bluetooth Low Energy air intefrace Link Layer"),
    NETLINK(253, "Linux Netlink"),
    BLUETOOTH_LINUX_MONITOR(254, "Bluetooth Linux Monitor"),
    BLUETOOTH_BREDR_BB(255, "Bluetooth Basic Rate and Enhanced Data Rate baseband"),
    BLUETOOTH_LE_LL_WITH_PHDR(256, "Bluetooth Low Energy link-layer pseudo-header"),
    PROFIBUS_DL(257, "PROFIBUS"),
    PKTAP(258, "Apple PKTAP"),
    EPON(259, "Ethernet-over-passive-optical-network"),
    IPMI_HPM_2(260, "IPMI trace"),
    ZWAVE_R1_R2(261, "Z-Wave RF profile R1 and R2"),
    ZWAPE_R3(262, "Z-Wave RF profile R3"),
    WATTSTOPPER_DLM(263, "WattStopper Digital Lightning Management"),
    ISO_14443(264, "ISO 14443"),
    RDS(265, "Radio data system"),
    USB_DARWIN(266, "Darwin USB"),
    SDLC(268, "SDLC"),
    LORATAP(270, "LoRaTap pseudo-header"),
    VSOCK(271, "VMware/KVM Hypervisor"),
    NORDIC_BLE(272, "Nordic Semiconductor nRF Sniffer"),
    DOCSIS_31_XRA31(273, "DOCSIS XRA31"),
    ETHERNET_MPACKET(274, "Ethernet mPacket"),
    DISPLAYPORT_AUX(275, "DisplayPort AUX"),
    LINUX_SLL2(276, "Linux \"cooked\" v2"),
    OPENVIZSLA(278, "Openvizsla FPGA-based USB sniffer"),
    EBHSCR(279, "Elektrobit High Speed Capture and Replay"),
    VPP_DISPATCH(280, "Record in trace from VPP graph"),
    DSA_TAG_BRCM(281, "Ethernet with Switch Tag inserted between"),
    DSA_TAG_BRCM_PREPEND(282, "Ethernet with Switch Tag inserted before"),
    IEEE802_15_4_TAP(283, "IEEE 802.15.4 Low-Rate Wireless Network TLV"),
    DSA_TAG_DSA(284, "Ethernet frame with Switch Tag inserted between"),
    DSA_TAG_EDSA(285, "Ethernet frame with Switch Tag inserted between"),
    ELEE(286, "ELEE"),
    WAVE_SERIAL(287, "Serial frame transmitted between host and Z-Wave"),
    USB_2_0(288, "USB 2.0"),
    ATSC_ALP(289, "ATSC Link-Layer Protocol"),
    ETW(290, "Event Tracing for Windows");

    private Integer dataLinkType;
    private String name;

    LinkLayerHeader(final Integer dataLinkType, final String name) {
        this.dataLinkType = dataLinkType;
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name;
    }

    public Integer getDataLinkType() {
        return dataLinkType;
    }

    public String getName() {
        return name;
    }

    public static LinkLayerHeader fromDataLinkType(final Integer dataLinkType) throws UnknownLinkLayerHeader {
        for(LinkLayerHeader linkLayerHeader : LinkLayerHeader.values())
            if (linkLayerHeader.dataLinkType.equals(dataLinkType))
                return linkLayerHeader;
        throw new UnknownLinkLayerHeader("LinkLayerHeader ("+dataLinkType+") unknown");
    }
}
