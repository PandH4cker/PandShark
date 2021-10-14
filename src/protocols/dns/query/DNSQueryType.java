package protocols.dns.query;

public enum DNSQueryType {
    HOSTADDR("A", 1, "Host Address"),
    IPV6ADDR("AAAA", 28, "IPv6 Address"),
    NAMESERVER("NS", 2, "Name Server"),
    MAIL_DESTINATION("MD", 3, "Mail Destination"),
    MAIL_FORWARDER("MF", 4, "Mail Forwarder"),
    CNAME("CNAME", 5, "Canonical Name"),
    SOA("SOA", 6, "Starts of Authority Zone"),
    MAILBOX("MB", 7, "Mailbox Domain Name"),
    MAILGROUP("MG", 8, "Mail Group Member"),
    MAILRENAME("MR", 9, "Mail Rename Domain Name"),
    NULL("NULL", 10, "Null RR"),
    WKS("WKS", 11, "Well-Known Service"),
    POINTER("PTR", 12, "Domain Name Pointer"),
    HINFO("HINFO", 13, "Host Information"),
    MINFO("MINFO", 14, "Mail List Information"),
    MAIL_EXCHANGE("MX", 15, "Mail Exchange"),
    TEXT("TXT", 16, "Text Strings");

    private String entry;
    private Integer value;
    private String name;

    DNSQueryType(final String entry, final Integer value, final String name) {
        this.entry = entry;
        this.value = value;
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getEntry() {
        return entry;
    }

    public Integer getValue() {
        return value;
    }
}
