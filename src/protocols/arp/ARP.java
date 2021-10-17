package protocols.arp;

import core.headers.layer2.Layer2Protocol;
import core.headers.layer3.Layer3Protocol;
import protocols.PcapPacketData;
import protocols.arp.exceptions.*;
import utils.net.IP;
import utils.net.MAC;

public class ARP extends PcapPacketData {
    private static final Integer SIZE = 28;

    private HardwareType hardwareType;
    private ProtocolType protocolType;
    private HardwareAddressLength hardwareAddressLength;
    private ProtocolAddressLength protocolAddressLength;
    private Operation operation;
    private String senderHardwareAddress;
    private String senderInternetAddress;
    private String targetHardwareAddress;
    private String targetInternetAddress;
    private String trailer;


    public ARP(final Integer id,
               final Integer sequenceNumber,
               final Layer2Protocol layer2Protocol,
               final Layer3Protocol layer3Protocol,
               final Integer hardwareType,
               final String protocolType,
               final Integer hardwareAddressLength,
               final Integer protocolAddressLength,
               final Integer operation,
               final String senderHardwareAddress,
               final String senderInternetAddress,
               final String targetHardwareAddress,
               final String targetInternetAddress,
               final String trailer) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol);
        try {
            this.hardwareType = HardwareType.fromCode(hardwareType);
            this.protocolType = ProtocolType.fromCodeType(protocolType);
            this.hardwareAddressLength = HardwareAddressLength.fromLength(hardwareAddressLength);
            this.protocolAddressLength = ProtocolAddressLength.fromLength(protocolAddressLength);
            this.operation = Operation.fromOpcode(operation);
        } catch (UnknownHardwareType | UnknownProtocolType | UnknownHardwareAddressLength |
                UnknownProtocolAddressLength | UnknownOperation e) {
            e.printStackTrace();
        }
        this.senderHardwareAddress = MAC.fromHexString(senderHardwareAddress);
        this.senderInternetAddress = IP.v4FromHexString(senderInternetAddress);
        this.targetHardwareAddress = MAC.fromHexString(targetHardwareAddress);
        this.targetInternetAddress = IP.v4FromHexString(targetInternetAddress);
        this.trailer = trailer;
    }

    public static Integer getSIZE() {
        return SIZE;
    }

    @Override
    public String toString() {
        return "Hardware type = " + this.hardwareType +
        "\nProtocol type = " + this.protocolType +
        "\nHardware size = " + this.hardwareAddressLength +
        "\nProtocol size = " + this.protocolAddressLength +
        "\nOpcode = " + this.operation +
        "\nSender MAC Address = " + this.senderHardwareAddress +
        "\nSender IP Address = " + this.senderInternetAddress +
        "\nTarget MAC Address = " + this.targetHardwareAddress +
        "\nTarget IP Address = " + this.targetInternetAddress;
    }

    public String getInfo() {
        switch (this.getOperation()) {
            case REQUEST -> {
                return "Who has " + this.getTargetInternetAddress() + "? Tell " + this.senderInternetAddress;
            }
            case REPLY -> {
                return this.senderInternetAddress + " is at " + this.senderHardwareAddress;
            }
            default -> {
                return null;
            }
        }
    }

    public Operation getOperation() {
        return operation;
    }

    public void setOperation(Operation operation) {
        this.operation = operation;
    }

    public String getTrailer() {
        return trailer;
    }

    public void setTrailer(String trailer) {
        this.trailer = trailer;
    }

    public HardwareType getHardwareType() {
        return hardwareType;
    }

    public void setHardwareType(HardwareType hardwareType) {
        this.hardwareType = hardwareType;
    }

    public ProtocolType getProtocolType() {
        return protocolType;
    }

    public void setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
    }

    public HardwareAddressLength getHardwareAddressLength() {
        return hardwareAddressLength;
    }

    public void setHardwareAddressLength(HardwareAddressLength hardwareAddressLength) {
        this.hardwareAddressLength = hardwareAddressLength;
    }

    public ProtocolAddressLength getProtocolAddressLength() {
        return protocolAddressLength;
    }

    public void setProtocolAddressLength(ProtocolAddressLength protocolAddressLength) {
        this.protocolAddressLength = protocolAddressLength;
    }

    public String getSenderHardwareAddress() {
        return senderHardwareAddress;
    }

    public void setSenderHardwareAddress(String senderHardwareAddress) {
        this.senderHardwareAddress = senderHardwareAddress;
    }

    public String getSenderInternetAddress() {
        return senderInternetAddress;
    }

    public void setSenderInternetAddress(String senderInternetAddress) {
        this.senderInternetAddress = senderInternetAddress;
    }

    public String getTargetHardwareAddress() {
        return targetHardwareAddress;
    }

    public void setTargetHardwareAddress(String targetHardwareAddress) {
        this.targetHardwareAddress = targetHardwareAddress;
    }

    public String getTargetInternetAddress() {
        return targetInternetAddress;
    }

    public void setTargetInternetAddress(String targetInternetAddress) {
        this.targetInternetAddress = targetInternetAddress;
    }
}
