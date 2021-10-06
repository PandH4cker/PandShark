package core.headers;

public class PcapGlobalHeader {
    private Integer uMagicNumber;
    private Integer uVersionMajor;
    private Integer uVersionMinor;
    private Integer thisZone;
    private Integer uSigFigs;
    private Integer uSnapLen;
    private Integer uNetwork;

    public PcapGlobalHeader(final Integer uMagicNumber,
                            final Integer uVersionMajor,
                            final Integer uVersionMinor,
                            final Integer thisZone,
                            final Integer uSigFigs,
                            final Integer uSnapLen,
                            final Integer uNetwork) {
        this.uMagicNumber = uMagicNumber;
        this.uVersionMajor = uVersionMajor;
        this.uVersionMinor = uVersionMinor;
        this.thisZone = thisZone;
        this.uSigFigs = uSigFigs;
        this.uSnapLen = uSnapLen;
        this.uNetwork = uNetwork;
    }

    public Integer getuMagicNumber() {
        return uMagicNumber;
    }

    public void setuMagicNumber(Integer uMagicNumber) {
        this.uMagicNumber = uMagicNumber;
    }

    public Integer getuVersionMajor() {
        return uVersionMajor;
    }

    public void setuVersionMajor(Integer uVersionMajor) {
        this.uVersionMajor = uVersionMajor;
    }

    public Integer getuVersionMinor() {
        return uVersionMinor;
    }

    public void setuVersionMinor(Integer uVersionMinor) {
        this.uVersionMinor = uVersionMinor;
    }

    public Integer getThisZone() {
        return thisZone;
    }

    public void setThisZone(Integer thisZone) {
        this.thisZone = thisZone;
    }

    public Integer getuSigFigs() {
        return uSigFigs;
    }

    public void setuSigFigs(Integer uSigFigs) {
        this.uSigFigs = uSigFigs;
    }

    public Integer getuSnapLen() {
        return uSnapLen;
    }

    public void setuSnapLen(Integer uSnapLen) {
        this.uSnapLen = uSnapLen;
    }

    public Integer getuNetwork() {
        return uNetwork;
    }

    public void setuNetwork(Integer uNetwork) {
        this.uNetwork = uNetwork;
    }
}
