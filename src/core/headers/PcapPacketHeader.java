package core.headers;

public class PcapPacketHeader {
    private Integer uTsSec;
    private Integer uTsUsec;
    private Integer uInclLen;
    private Integer uOrigLen;

    public PcapPacketHeader(final Integer uTsSec,
                            final Integer uTsUsec,
                            final Integer uInclLen,
                            final Integer uOrigLen) {
        this.uTsSec = uTsSec;
        this.uTsUsec = uTsUsec;
        this.uInclLen = uInclLen;
        this.uOrigLen = uOrigLen;
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
