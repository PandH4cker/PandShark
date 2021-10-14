package protocols.dns;

import protocols.dns.exceptions.UnknownRcode;

public enum Rcode {
    NO_ERROR(0, "No Error"),
    REQUEST_FORMAT_ERROR(1, "Request Format Error"),
    SERVER_ERROR(2, "Server Error"),
    UNKNOWN_NAME(3, "Unknown Name"),
    NOT_IMPLEMENTED(4, "Not Implemented"),
    FAILURE(5, "Failure");

    private Integer code;
    private String name;

    Rcode(final Integer code, final String name) {
        this.code = code;
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public static Rcode fromCode(final Integer code) throws UnknownRcode {
        for(Rcode rcode : Rcode.values())
            if (rcode.code.equals(code))
                return rcode;
        throw new UnknownRcode("UnknownRcode ("+code+") unknown");
    }
}
