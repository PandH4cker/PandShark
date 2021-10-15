package protocols.dns.query;

import protocols.dns.exceptions.UnknownQueryClass;
import protocols.dns.exceptions.UnknownQueryType;

public class DNSQuery {
    private String name;
    private DNSQueryType queryType;
    private DNSQueryClass queryClass;

    public DNSQuery(final String name,
                    final String entryQueryType,
                    final Integer valueQueryType,
                    final String entryQueryClass,
                    final Integer valueQueryClass) {
        this.name = name;
        try {
            this.queryType = DNSQueryType.fromEntryValue(entryQueryType, valueQueryType);
            this.queryClass = DNSQueryClass.fromEntryValue(entryQueryClass, valueQueryClass);
        } catch (UnknownQueryType e) {
            this.queryType = null;
        } catch (UnknownQueryClass unknownQueryClass) {
            this.queryClass = null;
        }
    }
}
