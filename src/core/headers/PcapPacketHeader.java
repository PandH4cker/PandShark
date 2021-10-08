package core.headers;

public class PcapPacketHeader {
    private Integer uTsSec; //32 bits
    private Integer uTsUsec; //32 bits
    private Integer uInclLen; //32 bits
    private Integer uOrigLen; //32 bits

    public PcapPacketHeader(final Integer uTsSec,
                            final Integer uTsUsec,
                            final Integer uInclLen,
                            final Integer uOrigLen) {
        this.uTsSec = uTsSec;
        this.uTsUsec = uTsUsec;
        this.uInclLen = uInclLen;
        this.uOrigLen = uOrigLen;
    }

    @Override
    public String toString() {
        return "** Packet Header **\n" +
                "Timestamp (s) = " + this.uTsSec +
                "\nTimestamp (µs) = " + this.uTsUsec +
                "\nIncluded Length = " + this.uInclLen + " bytes" +
                "\nOriginal Length = " + this.uOrigLen + " bytes";
    }

    public Integer getuTsSec() {
        return uTsSec;
    }

    public void setuTsSec(Integer uTsSec) {
        this.uTsSec = uTsSec;
    }

    public Integer getuTsUsec() {
        return uTsUsec;
    }

    public void setuTsUsec(Integer uTsUsec) {
        this.uTsUsec = uTsUsec;
    }

    public Integer getuInclLen() {
        return uInclLen;
    }

    public void setuInclLen(Integer uInclLen) {
        this.uInclLen = uInclLen;
    }

    public Integer getuOrigLen() {
        return uOrigLen;
    }

    public void setuOrigLen(Integer uOrigLen) {
        this.uOrigLen = uOrigLen;
    }
}
