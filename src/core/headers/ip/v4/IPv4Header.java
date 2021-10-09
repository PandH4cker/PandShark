package core.headers.ip.v4;

public class IPv4Header {
    private String versIHL;
    private String service;
    private Integer totalLength;
    private Integer identification;
    private String flagsPosition;
    private Integer ttl;
    private Integer protocol;
    private String checksum;
    private String sourceIP;
    private String destinationIP;

    public IPv4Header(final String versIHL,
                      final String service,
                      final Integer totalLength,
                      final Integer identification,
                      final String flagsPosition,
                      final Integer ttl,
                      final Integer protocol,
                      final String checksum,
                      final String sourceIP,
                      final String destinationIP) {
        this.versIHL = versIHL;
        this.service = service;
        this.totalLength = totalLength;
        this.identification = identification;
        this.flagsPosition = flagsPosition;
        this.ttl = ttl;
        this.protocol = protocol;
        this.checksum = checksum;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
    }

    public String getVersIHL() {
        return versIHL;
    }

    public void setVersIHL(String versIHL) {
        this.versIHL = versIHL;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public Integer getTotalLength() {
        return totalLength;
    }

    public void setTotalLength(Integer totalLength) {
        this.totalLength = totalLength;
    }

    public Integer getIdentification() {
        return identification;
    }

    public void setIdentification(Integer identification) {
        this.identification = identification;
    }

    public String getFlagsPosition() {
        return flagsPosition;
    }

    public void setFlagsPosition(String flagsPosition) {
        this.flagsPosition = flagsPosition;
    }

    public Integer getTtl() {
        return ttl;
    }

    public void setTtl(Integer ttl) {
        this.ttl = ttl;
    }

    public Integer getProtocol() {
        return protocol;
    }

    public void setProtocol(Integer protocol) {
        this.protocol = protocol;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public void setDestinationIP(String destinationIP) {
        this.destinationIP = destinationIP;
    }
}
