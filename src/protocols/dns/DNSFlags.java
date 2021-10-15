package protocols.dns;

import protocols.dns.exceptions.UnknownOpcode;
import protocols.dns.exceptions.UnknownRcode;

public class DNSFlags {
    private Boolean qr;
    private DNSOpcode opcode;
    private Boolean authoritativeAnswer;
    private Boolean truncated;
    private Boolean recursed;
    private Boolean authoritativeRecurse;
    private Integer z;
    private Rcode rcode;

    public DNSFlags(final Boolean qr,
                    final Integer opcode,
                    final Boolean authoritativeAnswer,
                    final Boolean truncated,
                    final Boolean recursed,
                    final Boolean authoritativeRecurse,
                    final Integer z,
                    final Integer rcode) {
        try {
            this.qr = qr;
            this.opcode = DNSOpcode.fromCode(opcode);
            this.authoritativeAnswer = authoritativeAnswer;
            this.truncated = truncated;
            this.recursed = recursed;
            this.authoritativeRecurse = authoritativeRecurse;
            this.z = z;
            this.rcode = Rcode.fromCode(rcode);
        } catch (UnknownOpcode ignored) {
            this.opcode = null;
        } catch (UnknownRcode ignored) {
            this.rcode = null;
        }
    }

    public Boolean getQr() {
        return qr;
    }

    public void setQr(Boolean qr) {
        this.qr = qr;
    }

    public DNSOpcode getOpcode() {
        return opcode;
    }

    public void setOpcode(DNSOpcode opcode) {
        this.opcode = opcode;
    }

    public Boolean getAuthoritativeAnswer() {
        return authoritativeAnswer;
    }

    public void setAuthoritativeAnswer(Boolean authoritativeAnswer) {
        this.authoritativeAnswer = authoritativeAnswer;
    }

    public Boolean getTruncated() {
        return truncated;
    }

    public void setTruncated(Boolean truncated) {
        this.truncated = truncated;
    }

    public Boolean getRecursed() {
        return recursed;
    }

    public void setRecursed(Boolean recursed) {
        this.recursed = recursed;
    }

    public Boolean getAuthoritativeRecurse() {
        return authoritativeRecurse;
    }

    public void setAuthoritativeRecurse(Boolean authoritativeRecurse) {
        this.authoritativeRecurse = authoritativeRecurse;
    }

    public Integer getZ() {
        return z;
    }

    public void setZ(Integer z) {
        this.z = z;
    }

    public Rcode getRcode() {
        return rcode;
    }

    public void setRcode(Rcode rcode) {
        this.rcode = rcode;
    }
}
