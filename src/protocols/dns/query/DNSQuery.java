package protocols.dns.query;

import protocols.dns.DNSClass;
import protocols.dns.DNSType;
import protocols.dns.exceptions.UnknownQueryClass;
import protocols.dns.exceptions.UnknownQueryType;

public class DNSQuery {
    private String name;
    private DNSType queryType;
    private DNSClass queryClass;

    public DNSQuery(final String name,
                    final Integer valueQueryType,
                    final Integer valueQueryClass) {
        this.name = name;
        try {
            this.queryType = DNSType.fromValue(valueQueryType);
            this.queryClass = DNSClass.fromValue(valueQueryClass);
        } catch (UnknownQueryType e) {
            this.queryType = null;
        } catch (UnknownQueryClass unknownQueryClass) {
            this.queryClass = null;
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public DNSType getQueryType() {
        return queryType;
    }

    public void setQueryType(DNSType queryType) {
        this.queryType = queryType;
    }

    public DNSClass getQueryClass() {
        return queryClass;
    }

    public void setQueryClass(DNSClass queryClass) {
        this.queryClass = queryClass;
    }
}
