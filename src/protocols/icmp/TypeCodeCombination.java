package protocols.icmp;

import protocols.icmp.exceptions.UnknownTypeCodeCombination;

public enum TypeCodeCombination {
    //Type 0
    ECHO_REPLY(0,0, "Echo Reply"),

    //Type 3
    NET_UNREACHABLE(3, 0, "Net Unreachable"),
    HOST_UNREACHABLE(3, 1, "Host Unreachable"),
    PROTOCOL_UNREACHABLE(3, 2, "Protocol Unreachable"),
    PORT_UNREACHABLE(3, 3, "Port Unreachable"),
    FRAGMENTATION_NEEDED_DF_SET(3, 4, "Fragmentation Needed and DF was Set"),
    SOURCE_ROUTE_FAILED(3, 5, "Source Route Failed"),
    DESTINATION_NET_UNKNOWN(3, 6, "Destination Network Unknown"),
    DESTINATION_HOST_UNKNOWN(3, 7, "Destination Host Unknown"),
    SOURCE_HOST_ISOLATED(3, 8, "Source Host Isolated"),
    COMMUNICATION_W_DESTINATION_NET_PROHIB(
            3,
            9,
            "Communication with Destination Network is Administratively Prohibited"
    ),
    COMMUNICATION_W_DESTINATION_HOST_PROHIB(
            3,
            10,
            "Communication with Destination Host is Administratively Prohibited"
    ),
    DESTINATION_NET_UNREACHABLE(3, 11, "Destination Network Unreachable"),
    DESTINATION_HOST_UNREACHABLE(3, 12, "Destination Host Unreachable"),
    COMMUNICATION_ADMIN_PROHIB(3, 13, "Communication Administratively Prohibited"),
    HOST_PRECEDENCE_VIOLATION(3, 14, "Host Precedence Violation"),
    PRECEDENCE_CUTOFF(3, 15, "Precedence Cutoff"),

    //Type 4 (Deprecated)
    SOURCE_QUENCH(4, 0, "Source Quench"),

    //Type 5
    REDIRECT_HOST(5, 0, "Redirect for the Host"),
    REDIRECT_SERVICE_HOST(5, 1, "Redirect for the Service and Host"),
    REDIRECT_NET(5, 2, "Redirect for the Network"),
    REDIRECT_SERVICE_NET(5, 3, "Redirect for the Service and Network"),

    //Type 8
    ECHO_REQUEST(8, 0, "Echo Request"),

    //Type 9
    ROUTER_ADVERTISEMENT(9, 0, "Router Advertisement"),

    //Type 10
    ROUTER_SELECTION(10, 0, "Router Selection"),

    //Type 11
    TTL_EXCEEDED(11, 0, "Time to Live Exceeded in Transit"),
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED(11, 1, "Fragment Reassembly Time Exceeded"),

    //Type 12
    INVALID_IP_HEADER(12, 0, "Invalid IP Header"),
    MISSING_REQUIRED_OPTION(12, 1, "Missing Required Option"),
    BAD_LENGTH(12, 2, "Bad Length"),

    //Type 13
    TIMESTAMP_REQUEST(13, 0, "Timestamp Request"),

    //Type 14
    TIMESTAMP_REPLY(14, 0, "Timestamp Reply"),

    //Type 15 (Deprecated)
    NET_ADDRESS_REQUEST(15, 0, "Network Address Request"),

    //Type 16 (Deprecated)
    NET_ADDRESS_REPLY(16, 0, "Network Address Reply"),

    //Type 17 (Deprecated)
    NETMASK_REQUEST(17, 0, "Netmask Request"),

    //Type 18 (Deprecated)
    NETMASK_REPLY(18, 0, "Netmask Reply");

    private final Integer type;
    private final Integer code;
    private final String name;

    TypeCodeCombination(final Integer type, final Integer code, final String name) {
        this.type = type;
        this.code = code;
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name;
    }

    public static TypeCodeCombination fromTypeCode(final Integer type, final Integer code) throws UnknownTypeCodeCombination {
        for(TypeCodeCombination codeCombination : TypeCodeCombination.values())
            if (codeCombination.type.equals(type) && codeCombination.code.equals(code))
                return codeCombination;
        throw new UnknownTypeCodeCombination("TypeCodeCombination ("+type+","+code+") unknown");
    }
}
