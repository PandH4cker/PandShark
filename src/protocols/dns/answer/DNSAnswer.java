package protocols.dns.answer;

import protocols.dns.DNSClass;
import protocols.dns.DNSType;
import protocols.dns.exceptions.UnknownQueryClass;
import protocols.dns.exceptions.UnknownQueryType;
import utils.date.DateArithmetic;
import utils.hex.Hexlifier;
import utils.net.IP;

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
        } catch (UnknownQueryType e) {
            this.type = null;
        }
        try {
            this.dnsClass = DNSClass.fromValue(dnsClass);
        } catch (UnknownQueryClass unknownQueryClass) {
            this.dnsClass = null;
        }
        this.ttl = ttl;
        this.dataLength = dataLength;
        this.data = data;
        /*this.data = this.type != null ? switch (this.type) {
            case HOSTADDR -> {
                String ipv4 = IP.v4FromHexString(data.substring(2));
                this.data = "Address: " + ipv4;
                yield this.data;
            }
            case IPV6ADDR -> {
                String ipv6 = IP.v6FromHexString(data.substring(2));
                this.data = "Address: " + ipv6;
                yield this.data;
            }
            case CNAME -> {
                String cname = Hexlifier.unhexlify(data.substring(2));
                this.data = "CNAME: " + this.name.replaceFirst("[^.]*", cname);
                System.out.println("Errored value = " + (int) this.data.charAt(this.data.length() - 1));
                yield this.data;
            }
            default -> data;
        } : data;*/
    }

    @Override
    public String toString() {
        return "Name = " + this.name +
                "\nType = " + (this.type != null ? this.type + " (" + this.type.getEntry() + ")" : "Unknown") +
                "\nClass = " + (this.dnsClass != null ? this.dnsClass + " (" + this.dnsClass.getEntry() + ")" : "Unknown") +
                "\nTime To Live = " + this.ttl + " (" + DateArithmetic.toMinutes(this.ttl) + " minutes)" +
                "\nData Length = " + this.dataLength +
                "\n" + this.data;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public DNSType getType() {
        return type;
    }

    public void setType(DNSType type) {
        this.type = type;
    }

    public DNSClass getDnsClass() {
        return dnsClass;
    }

    public void setDnsClass(DNSClass dnsClass) {
        this.dnsClass = dnsClass;
    }

    public Integer getTtl() {
        return ttl;
    }

    public void setTtl(Integer ttl) {
        this.ttl = ttl;
    }

    public Integer getDataLength() {
        return dataLength;
    }

    public void setDataLength(Integer dataLength) {
        this.dataLength = dataLength;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
