package protocols.arp;

import protocols.arp.exceptions.UnknownHardwareAddressLength;

public enum HardwareAddressLength {
    TOKEN_RING(1, "Token Ring"),
    ETHERNET(6, "Ethernet");

    private Integer length;
    private String name;

    HardwareAddressLength(final Integer length, final String name) {
        this.length = length;
        this.name = name;
    }

    public Integer getLength() {
        return length;
    }

    @Override
    public String toString() {
        return name;
    }

    public static HardwareAddressLength fromLength(final Integer length) throws UnknownHardwareAddressLength {
        for(HardwareAddressLength hal : HardwareAddressLength.values())
            if (hal.length.equals(length))
                return hal;
        throw new UnknownHardwareAddressLength("HardwareAddressLength ("+length+") unknown");
    }

}
