package protocols.dns.answer;

import protocols.dns.DNSClass;
import protocols.dns.DNSType;
import protocols.dns.exceptions.UnknownQueryClass;
import protocols.dns.exceptions.UnknownQueryType;

public class DNSAnswer {
    private String name;
    private DNSType type;
    private DNSClass dnsClass;
    private Integer ttl;
    private Integer dataLength;
    private String data;

    public DNSAnswer(final String name,
                     final Integer type,
                     final Integer dnsClass,
                     final Integer ttl,
                     final Integer dataLength,
                     final String data) {
        this.name = name;
        try {
            this.type = DNSType.fromValue(type);
            this.dnsClass = DNSClass.fromValue(dnsClass);
            this.ttl = ttl;
            this.dataLength = dataLength;
            this.data = data;
        } catch (UnknownQueryType e) {
            this.type = null;
        } catch (UnknownQueryClass unknownQueryClass) {
            this.dnsClass = null;
        }
    }
}
