package core.headers.layer4.tcp;

public class TCPFlags {
    private Boolean urg;
    private Boolean ack;
    private Boolean psh;
    private Boolean rst;
    private Boolean syn;
    private Boolean fin;

    public TCPFlags(final Boolean urg,
                    final Boolean ack,
                    final Boolean psh,
                    final Boolean rst,
                    final Boolean syn,
                    final Boolean fin) {
        this.urg = urg;
        this.ack = ack;
        this.psh = psh;
        this.rst = rst;
        this.syn = syn;
        this.fin = fin;
    }

    public Boolean getUrg() {
        return urg;
    }

    public void setUrg(Boolean urg) {
        this.urg = urg;
    }

    public Boolean getAck() {
        return ack;
    }

    public void setAck(Boolean ack) {
        this.ack = ack;
    }

    public Boolean getPsh() {
        return psh;
    }

    public void setPsh(Boolean psh) {
        this.psh = psh;
    }

    public Boolean getRst() {
        return rst;
    }

    public void setRst(Boolean rst) {
        this.rst = rst;
    }

    public Boolean getSyn() {
        return syn;
    }

    public void setSyn(Boolean syn) {
        this.syn = syn;
    }

    public Boolean getFin() {
        return fin;
    }

    public void setFin(Boolean fin) {
        this.fin = fin;
    }
}
