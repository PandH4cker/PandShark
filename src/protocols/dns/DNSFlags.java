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
    private Boolean z;
    private Rcode rcode;

    public DNSFlags(final Boolean qr,
                    final Integer opcode,
                    final Boolean authoritativeAnswer,
                    final Boolean truncated,
                    final Boolean recursed,
                    final Boolean authoritativeRecurse,
                    final Boolean z,
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
}
